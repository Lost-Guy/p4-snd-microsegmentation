#!/usr/bin/env python2
import subprocess
import sys
import time
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../controller'))
import p4runtime_client

def get_host_pid(host_name):
    try:
        pid = subprocess.check_output(["pgrep", "-f", "mininet:{}".format(host_name)]).strip().splitlines()[0]
        return pid
    except Exception:
        return None

def run_udp_traffic_test(src_host, dst_host, dst_ip, packet_count, delay, listen_timeout=3.0):
    """Starts a UDP listener on dst_host and sends packets from src_host."""
    src_pid = get_host_pid(src_host)
    dst_pid = get_host_pid(dst_host)
    if not src_pid or not dst_pid:
        return -1

    # Receiver script
    recv_script = """
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 5001))
s.settimeout(1.0)
c = 0
start = time.time()
while time.time() - start < {0}:
    try:
        _, _ = s.recvfrom(1024)
        c += 1
        if c >= {1}:
            break
    except socket.timeout:
        break
    except Exception as e:
        sys.stderr.write(str(e))
        break
print(c)
""".format(listen_timeout, packet_count)

    recv_proc = subprocess.Popen(
        ["nsenter", "-t", dst_pid, "-n", "python", "-c", recv_script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    time.sleep(0.3) # Allow receiver socket to bind

    # Sender script: if delay > 0 use sleep, else blast back-to-back
    if delay > 0:
        send_script = """
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range({0}):
    s.sendto('DDOS_PAYLOAD', ('{1}', 5001))
    time.sleep({2})
""".format(packet_count, dst_ip, delay)
    else:
        send_script = """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range({0}):
    s.sendto('DDOS_PAYLOAD', ('{1}', 5001))
""".format(packet_count, dst_ip)

    send_proc = subprocess.Popen(
        ["nsenter", "-t", src_pid, "-n", "python", "-c", send_script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    send_proc.wait()

    stdout, stderr = recv_proc.communicate()
    if stderr.strip():
        sys.stderr.write("[Receiver Log]: " + stderr.strip() + "\n")
    try:
        return int(stdout.strip())
    except Exception:
        return 0

def run_ddos_test_suite():
    print("==================================================")
    print("    DDoS FLOOD MITIGATION TEST SUITE (P4 METER)   ")
    print("==================================================\n")

    print("[+] Reprogramming pipeline and configuring DDoS meter rates...")
    p4runtime_client.main()
    p4runtime_client.configure_ddos_mitigation(9090)
    p4runtime_client.configure_ddos_mitigation(9091)

    print("\n[+] Dynamically permitting UDP traffic (proto 17) for h1 <-> h2...")
    p4runtime_client.dynamic_permit_flow(9090, "10.0.0.1", "10.0.0.2", 17)
    p4runtime_client.dynamic_permit_flow(9091, "10.0.0.1", "10.0.0.2", 17)
    time.sleep(1)

    # Test 1: Low-Rate Legitimate Traffic (5 pkts @ 10 pkts/sec -> well below 100 pkts/sec CIR)
    print("\n--- Test 1: Low-Rate Legitimate Traffic (5 pkts @ 10 pkts/sec) ---")
    received_low = run_udp_traffic_test("h1", "h2", "10.0.0.2", packet_count=5, delay=0.1, listen_timeout=3.0)
    print("Sent: 5 packets | Received: {} packets".format(received_low))
    status_low = "PASS" if received_low == 5 else "FAIL"
    print("[{}] Low-rate traffic permitted through data plane.".format(status_low))

    # Test 2: Unthrottled Volumetric Flood Attack (300 pkts back-to-back -> exceeds PIR & PBS)
    print("\n--- Test 2: Volumetric Flood Attack (300 pkts back-to-back) ---")
    received_flood = run_udp_traffic_test("h1", "h2", "10.0.0.2", packet_count=300, delay=0.0, listen_timeout=3.0)
    dropped = 300 - received_flood
    loss_pct = (float(dropped) / 300.0) * 100.0
    print("Sent: 300 packets | Received: {} packets | Dropped: {} packets ({:.1f}% Loss)".format(
        received_flood, dropped, loss_pct
    ))

    status_flood = "PASS" if loss_pct >= 70.0 else "FAIL"
    print("[{}] Volumetric flood mitigated at line rate by P4 meter (RED drops).".format(status_flood))

    print("\n==================================================")
    print("          DDoS MITIGATION TEST COMPLETE           ")
    print("==================================================")

if __name__ == "__main__":
    run_ddos_test_suite()
