#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"
#include "ingress.p4"
#include "telemetry.p4"

control TopVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control TopComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control TopMicrosegmentation(inout headers hdr,
                             inout metadata meta,
                             inout standard_metadata_t standard_metadata) {

	direct_counter(CounterType.packets_and_bytes) microseg_counter;

    action allow() {
        microseg_counter.count();
    }

    action drop_flow() {
		microseg_counter.count();
        mark_to_drop(standard_metadata);
    }

    table tbl_microsegmentation {
        key = {
            hdr.ipv4.srcAddr  : exact;
            hdr.ipv4.dstAddr  : exact;
            hdr.ipv4.protocol : exact;
        }
        actions = {
            allow;
            drop_flow;
        }
        default_action = drop_flow();
		counters = microseg_counter;
        size = 1024;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (!tbl_microsegmentation.apply().hit) {
                drop_flow();
            }
        }
    }
}

control PipelineIngress(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {

    TopIngressTelemetry() telemetry;
	TopMicrosegmentation() microsegmentation;
    TopIngress() forwarding;

    apply {
        telemetry.apply(hdr, meta, standard_metadata);
        forwarding.apply(hdr, meta, standard_metadata);
		microsegmentation.apply(hdr, meta, standard_metadata);
    }
}

V1Switch(
    TopParser(),
    TopVerifyChecksum(),
    PipelineIngress(),
    TopEgress(),
    TopComputeChecksum(),
    TopDeparser()
) main;
