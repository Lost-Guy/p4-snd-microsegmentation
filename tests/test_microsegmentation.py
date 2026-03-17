#!/usr/bin/env python2
import subprocess
import sys
import time
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../controller'))
import p4runtime_client

def get_host_pid(host_name):
    """Retrieve process ID for a Mininet host."""
    try:
        pid = subprocess.check_output(["pgrep", "-f", "mininet:{}".format(host_name)]).strip().splitlines()[0]
        return pid
    except Exception:
        return None

def exec_ping(src_host, dst_ip, count=2, timeout=1):
    """Execute ping from src_host network namespace to dst_ip."""
    pid = get_host_pid(src_host)
    if not pid:
        return False, "Host {} PID not found".format(src_host)
    
    cmd = ["nsenter", "-t", pid, "-n", "ping", "-c", str(count), "-W", str(timeout), dst_ip]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return (proc.returncode == 0), stdout

def run_test_suite():
    print("==================================================")
    print("  ZERO-TRUST MICRO-SEGMENTATION AUTOMATED SUITE   ")
    print("==================================================\n")

    # 1. Reset pipeline to baseline state
    print("[+] Reprogramming baseline L3 and Micro-segmentation rules...")
    p4runtime_client.main()
    time.sleep(1)

    # Matrix Definition: (src, dst_ip, expected_success, label)
    test_cases = [
        ("h1", "10.0.0.2", True,  "Intra-switch Permitted (h1 -> h2)"),
        ("h1", "10.0.0.3", True,  "Inter-switch Permitted (h1 -> h3)"),
        ("h2", "10.0.0.3", False, "Inter-switch Lateral Drop (h2 -> h3)"),
        ("h1", "10.0.0.4", False, "Host Quarantine Drop (h1 -> h4)"),
        ("h2", "10.0.0.4", False, "Host Quarantine Drop (h2 -> h4)"),
        ("h3", "10.0.0.4", False, "Host Quarantine Drop (h3 -> h4)"),
    ]

    passed = 0
    total = len(test_cases)

    print("\n--- Testing Baseline Micro-Segmentation Policy Matrix ---")
    for src, dst_ip, expected, label in test_cases:
        success, _ = exec_ping(src, dst_ip)
        status = "PASS" if success == expected else "FAIL"
        if success == expected:
            passed += 1
        print("[{}] {} | Expected: {} | Got: {}".format(
            status, label.ljust(42), "ALLOW" if expected else "BLOCK", "ALLOW" if success else "BLOCK"
        ))

    # 2. Test Dynamic Policy Granting
    print("\n--- Testing Dynamic Policy Enforcement (Unblocking h1 -> h4) ---")
    p4runtime_client.dynamic_permit_flow(9090, "10.0.0.1", "10.0.0.4", 1)
    p4runtime_client.dynamic_permit_flow(9091, "10.0.0.1", "10.0.0.4", 1)
    time.sleep(1)

    dyn_success, _ = exec_ping("h1", "10.0.0.4")
    dyn_status = "PASS" if dyn_success else "FAIL"
    if dyn_success:
        passed += 1
    total += 1
    print("[{}] Dynamic Policy Modification (h1 -> h4) | Expected: ALLOW | Got: {}".format(
        dyn_status, "ALLOW" if dyn_success else "BLOCK"
    ))

    # 3. Telemetry Direct Counter Verification
    print("\n--- Verifying Data Plane Telemetry Counters ---")
    p4runtime_client.fetch_telemetry(9090, "s1")

    print("\n==================================================")
    print(" TEST RESULTS: {}/{} TEST CASES PASSED".format(passed, total))
    print("==================================================")

if __name__ == "__main__":
    run_test_suite()
