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
    apply {}
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
