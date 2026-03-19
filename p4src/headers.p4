#ifndef _HEADERS_P4_
#define _HEADERS_P4_

#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// Layer 2: Ethernet Header (112 bits = 14 bytes)
header ethernet_t {
    macAddr_t dstAddr;   // 48 bits
    macAddr_t srcAddr;   // 48 bits
    bit<16>   etherType; // 16 bits
}

// Layer 3: IPv4 Header (160 bits = 20 bytes)
header ipv4_t {
    bit<4>    version;      // 4 bits
    bit<4>    ihl;          // 4 bits
    bit<8>    diffserv;     // 8 bits
    bit<16>   totalLen;     // 16 bits
    bit<16>   identification;// 16 bits
    bit<3>    flags;        // 3 bits
    bit<13>   fragOffset;   // 13 bits (3 + 13 = 16 bits)
    bit<8>    ttl;          // 8 bits
    bit<8>    protocol;     // 8 bits
    bit<16>   hdrChecksum;  // 16 bits
    ip4Addr_t srcAddr;      // 32 bits
    ip4Addr_t dstAddr;      // 32 bits
}

// Layer 4: TCP Header (160 bits = 20 bytes)
header tcp_t {
    bit<16> srcPort;    // 16 bits
    bit<16> dstPort;    // 16 bits
    bit<32> seqNo;      // 32 bits
    bit<32> ackNo;      // 32 bits
    bit<4>  dataOffset; // 4 bits
    bit<4>  res;        // 4 bits
    bit<8>  flags;      // 8 bits (4 + 4 + 8 = 16 bits)
    bit<16> window;     // 16 bits
    bit<16> checksum;   // 16 bits
    bit<16> urgPtr;     // 16 bits
}

// Custom Metadata passed across pipeline controls
struct metadata {
    bit<32> flow_packet_count;
	bit<8> meter_color;
}

// Master Header Struct containing parsed protocol fields
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

#endif // _HEADERS_P4_
