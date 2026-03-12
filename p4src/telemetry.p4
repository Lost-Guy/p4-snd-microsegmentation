#ifndef _TELEMETRY_P4_
#define _TELEMETRY_P4_

#include <core.p4>
#include <v1model.p4>
#include "headers.p4"

// Structure sent across CPU control port to the P4Runtime controller
struct digest_data_t {
    ip4Addr_t src_ip;
    bit<32>   packet_count;
}

control TopIngressTelemetry(inout headers hdr,
                            inout metadata meta,
                            inout standard_metadata_t standard_metadata) {

    // Array of 1024 registers stored in switch RAM to track packet counts per IP bucket
    register<bit<32>>(1024) ip_packet_counts;

    apply {
        if (hdr.ipv4.isValid()) {
            bit<32> hash_index;
            
            // Hash the source IP address into one of 1024 register buckets
            hash(hash_index, HashAlgorithm.crc16, (bit<32>)0, { hdr.ipv4.srcAddr }, (bit<32>)1024);

            bit<32> current_count;
            ip_packet_counts.read(current_count, hash_index);
            current_count = current_count + 1;
            ip_packet_counts.write(hash_index, current_count);

            meta.flow_packet_count = current_count;

            // Offloading condition: periodic alert every 64 packets once threshold > 64 is reached
            // (current_count & 0x3F == 0 checks if lower 6 bits are zero)
            if (current_count > 64 && (current_count & 0x3F) == 0) {
                digest_data_t data;
                data.src_ip = hdr.ipv4.srcAddr;
                data.packet_count = current_count;
                digest<digest_data_t>(1, data);
            }
        }
    }
}

#endif // _TELEMETRY_P4_
