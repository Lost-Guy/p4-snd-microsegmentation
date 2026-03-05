#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"

control TopVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control TopIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {
    apply {}
}

control TopEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply {}
}

control TopComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

V1Switch(
    TopParser(),
    TopVerifyChecksum(),
    TopIngress(),
    TopEgress(),
    TopComputeChecksum(),
    TopDeparser()
) main;
