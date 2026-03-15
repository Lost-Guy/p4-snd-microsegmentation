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

control PipelineIngress(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {

    TopIngressTelemetry() telemetry;
    TopIngress() forwarding;

    apply {
        telemetry.apply(hdr, meta, standard_metadata);
        forwarding.apply(hdr, meta, standard_metadata);
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
