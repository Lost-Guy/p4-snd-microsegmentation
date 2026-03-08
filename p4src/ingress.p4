#ifndef _INGRESS_P4_
#define _INGRESS_P4_

#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

control TopIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    // Action: Mark packet for dropping
    action drop_flow() {
        mark_to_drop(standard_metadata);
    }

    // Action: Standard L3 IPv4 forwarding
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Micro-segmentation isolation table (populating rules dynamically via P4Runtime)
    table tbl_microseg {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort:  exact;
        }
        actions = {
            drop_flow;
            NoAction;
        }
        default_action = NoAction();
    }

    // Standard L3 IPv4 routing table
    table tbl_ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop_flow;
            NoAction;
        }
        default_action = drop_flow();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            // Evaluate micro-segmentation quarantine first
            if (tbl_microseg.apply().hit) {
                // Flow matched an active quarantine rule
            } else {
                // Fall back to standard routing
                tbl_ipv4_lpm.apply();
            }
        }
    }
}

control TopEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply {}
}

#endif // _INGRESS_P4_
