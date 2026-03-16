#!/usr/bin/env python2
import sys
import os
import subprocess
import threading

# Polyfill Python 2.7 threading.Thread for 'daemon' kwarg compatibility
_old_thread_init = threading.Thread.__init__
def _new_thread_init(self, *args, **kwargs):
    daemon = kwargs.pop('daemon', None)
    _old_thread_init(self, *args, **kwargs)
    if daemon is not None:
        self.daemon = daemon
threading.Thread.__init__ = _new_thread_init

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../utils'))
sys.path.append('/workspace/utils')

def run_thrift_cli(thrift_port, cli_commands):
    """Execute commands on simple_switch_CLI and return output."""
    input_str = "\n".join(cli_commands) + "\n"
    proc = subprocess.Popen(
        ['simple_switch_CLI', '--thrift-port', str(thrift_port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate(input=input_str)
    return stdout, stderr

def discover_switch_schema(thrift_port=9090):
    """Query simple_switch_CLI directly for active table and action names."""
    out, _ = run_thrift_cli(thrift_port, ["show_tables"])
    discovered_tables = []
    
    for line in out.splitlines():
        if "RuntimeCmd:" in line and "[" in line:
            clean_line = line.replace("RuntimeCmd:", "").strip()
            parts = clean_line.split()
            if parts and not parts[0].startswith("Error"):
                discovered_tables.append(parts[0])

    selected_table = None
    for t in discovered_tables:
        if "lpm" in t.lower() or "ipv4" in t.lower() or "forward" in t.lower():
            selected_table = t
            break
    if not selected_table and discovered_tables:
        selected_table = discovered_tables[0]

    selected_action = "ipv4_forward"
    return selected_table, selected_action, discovered_tables

def configure_host_namespaces():
    """Inject static ARP entries and disable checksum offloading across host network namespaces."""
    hosts = {
        'h1': ('10.0.0.1', '00:04:00:00:01:01'),
        'h2': ('10.0.0.2', '00:04:00:00:02:01'),
        'h3': ('10.0.0.3', '00:04:00:00:03:01'),
        'h4': ('10.0.0.4', '00:04:00:00:04:01'),
    }

    host_pids = {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            cmd = ['nsenter', '-t', pid, '-n', 'ip', 'link']
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, _ = proc.communicate()
            for h in hosts.keys():
                if (h + '-eth0') in out:
                    host_pids[h] = pid
        except Exception:
            pass

    print("Discovered host network namespaces: {}".format(host_pids))

    for src_host, pid in host_pids.items():
        src_iface = src_host + '-eth0'
        # Disable checksum offloading so host kernels do not drop modified packets
        subprocess.call(
            ['nsenter', '-t', pid, '-n', 'ethtool', '-K', src_iface, 'rx', 'off', 'tx', 'off'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        for dst_host, (dst_ip, dst_mac) in hosts.items():
            if src_host != dst_host:
                cmd = [
                    'nsenter', '-t', pid, '-n',
                    'ip', 'neigh', 'replace', dst_ip, 'lladdr', dst_mac, 'dev', src_iface
                ]
                subprocess.call(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print("Host namespaces configured with static ARP and rx/tx checksum offloading disabled.")

def program_microsegmentation(thrift_port):
    """Inject zero-trust policy rules into tbl_microsegmentation."""
    table = "PipelineIngress.microsegmentation.tbl_microsegmentation"
    action = "PipelineIngress.microsegmentation.allow"
    
    cmds = [
        "table_clear " + table,
        # Allow h1 (10.0.0.1) <-> h2 (10.0.0.2) ICMP
        "table_add {} {} 10.0.0.1 10.0.0.2 1 =>".format(table, action),
        "table_add {} {} 10.0.0.2 10.0.0.1 1 =>".format(table, action),
        # Allow h1 (10.0.0.1) <-> h3 (10.0.0.3) ICMP
        "table_add {} {} 10.0.0.1 10.0.0.3 1 =>".format(table, action),
        "table_add {} {} 10.0.0.3 10.0.0.1 1 =>".format(table, action),
        "table_dump " + table
    ]
    out, _ = run_thrift_cli(thrift_port, cmds)
    print("Micro-segmentation policy output (port {}):\n{}".format(thrift_port, out))

def main():
    table_name, action_name, available_tables = discover_switch_schema(9090)
    print("Discovered runtime tables: {}".format(available_tables))
    print("Targeting -> Table: '{}', Action: '{}'".format(table_name, action_name))

    # Exact end-to-end host MAC mappings
    s1_rules = [
        {'match_ip': '10.0.0.1', 'prefix': 32, 'mac': '00:04:00:00:01:01', 'port': 1},
        {'match_ip': '10.0.0.2', 'prefix': 32, 'mac': '00:04:00:00:02:01', 'port': 2},
        {'match_ip': '10.0.0.3', 'prefix': 32, 'mac': '00:04:00:00:03:01', 'port': 3},
        {'match_ip': '10.0.0.4', 'prefix': 32, 'mac': '00:04:00:00:04:01', 'port': 3},
    ]

    s2_rules = [
        {'match_ip': '10.0.0.1', 'prefix': 32, 'mac': '00:04:00:00:01:01', 'port': 3},
        {'match_ip': '10.0.0.2', 'prefix': 32, 'mac': '00:04:00:00:02:01', 'port': 3},
        {'match_ip': '10.0.0.3', 'prefix': 32, 'mac': '00:04:00:00:03:01', 'port': 1},
        {'match_ip': '10.0.0.4', 'prefix': 32, 'mac': '00:04:00:00:04:01', 'port': 2},
    ]

    configure_host_namespaces()

    # Program switch s1
    print("\n--- Programming Switch s1 (Thrift port 9090) ---")
    s1_cmds = ["table_clear " + table_name]
    for r in s1_rules:
        s1_cmds.append("table_add {} {} {}/{} => {} {}".format(
            table_name, action_name, r['match_ip'], r['prefix'], r['mac'], r['port']
        ))
    s1_cmds.append("table_dump " + table_name)
    out1, _ = run_thrift_cli(9090, s1_cmds)
    print("CLI Output (s1):\n" + out1)

    # Program switch s2
    print("\n--- Programming Switch s2 (Thrift port 9091) ---")
    s2_cmds = ["table_clear " + table_name]
    for r in s2_rules:
        s2_cmds.append("table_add {} {} {}/{} => {} {}".format(
            table_name, action_name, r['match_ip'], r['prefix'], r['mac'], r['port']
        ))
    s2_cmds.append("table_dump " + table_name)
    out2, _ = run_thrift_cli(9091, s2_cmds)
    print("CLI Output (s2):\n" + out2)

    print("\nP4 forwarding tables and host namespaces successfully programmed.")

    # Program Micro-Segmentation Policies
    program_microsegmentation(9090)
    program_microsegmentation(9091)

if __name__ == '__main__':
    main()
