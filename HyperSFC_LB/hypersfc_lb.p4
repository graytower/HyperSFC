/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TOCPU_LOOKUP = 0x801;
const bit<16> TOCPU_DONF = 0x802;
const bit<16> TOCPU_RECV = 0x803;
const bit<8>  TYPE_TCP  = 6;

const bit<6>  ECMP_GROUP_TABLE_ID = 1;
const bit<2>  ECMP_GROUP_KEY_NUMBER = 1;
const bit<6>  ECMP_NHOP_TABLE_ID = 2;
const bit<2>  ECMP_NHOP_KEY_NUMBER = 1;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header key_t {
    bit<6>    keyOffset;
    bit<2>    matchType; //1:lpm 2:exact 3:ternary
    bit<64>   keyData;
}

header table_recv_t {
    bit<6>    tableId;
    bit<1>    lookUpResult;
    bit<1>    bos;
}

header table_send_t {
    bit<6>    tableId;
    bit<2>    keyNumber;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<14> ecmp_select;
    bit<6>  tmpoffset;
    bit<2>  tmpmatchtype;
    bit<64> tmpkey;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    key_t        key;
    table_recv_t table_recv;
    table_send_t table_send;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TOCPU_RECV: parse_table_recv;
            default: accept;
        }
    }
    state parse_table_recv {
        packet.extract(hdr.table_recv);
        transition parse_ipv4;
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action tocpu(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table_send.setValid();
        hdr.table_send.tableId = tableid;
        hdr.table_send.keyNumber = keynumber;
        hdr.key.setValid();
        hdr.key.keyOffset = meta.tmpoffset;
        hdr.key.matchType = meta.tmpmatchtype;
        hdr.key.keyData = meta.tmpkey;
    }
    
    action set_ecmp_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        hash(meta.ecmp_select,
            HashAlgorithm.crc16,
            ecmp_base,
            { hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort },
            ecmp_count);
    }
    action set_nhop(bit<48> nhop_dmac, bit<32> nhop_ipv4, bit<9> port) {
        hdr.ethernet.dstAddr = nhop_dmac;
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ecmp_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(ECMP_GROUP_TABLE_ID, ECMP_GROUP_KEY_NUMBER);
    }
    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            set_nhop;
            tocpu;
        }
        size = 2;
        default_action = tocpu(ECMP_NHOP_TABLE_ID, ECMP_NHOP_KEY_NUMBER);
    }
    apply {
        if(hdr.ethernet.etherType == TOCPU_RECV){
            drop();
        }
        else{
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == ECMP_GROUP_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
            else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == ECMP_GROUP_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                hdr.ethernet.etherType = TYPE_IPV4;
                ecmp_group.apply();
            }
            if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == ECMP_NHOP_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
            else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == ECMP_NHOP_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
                meta.tmpoffset = 14;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)meta.ecmp_select;
                hdr.ethernet.etherType = TYPE_IPV4;
                ecmp_nhop.apply();
            }
        }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        if (hdr.ethernet.etherType == TYPE_IPV4){
            hdr.table_send.setInvalid();
            hdr.key.setInvalid();
        }
    
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.table_send);
        packet.emit(hdr.key);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
