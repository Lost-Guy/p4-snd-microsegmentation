#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"
#include "ingress.p4"

control TopVerifyChecksum(inout headers hdr, inout metadata meta) {
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
