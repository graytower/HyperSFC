/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TOCPU_LOOKUP = 0x801;
const bit<16> TOCPU_DONF = 0x802;
const bit<16> TOCPU_RECV = 0x803;
const bit<8>  TYPE_TCP  = 6;

const bit<6>  IPV4_1_TABLE_ID = 1;
const bit<6>  IPV4_2_TABLE_ID = 2;
const bit<6>  IPV4_3_TABLE_ID = 3;
const bit<6>  IPV4_4_TABLE_ID = 4;
const bit<6>  IPV4_5_TABLE_ID = 5;
const bit<6>  IPV4_6_TABLE_ID = 6;
const bit<6>  IPV4_7_TABLE_ID = 7;
const bit<6>  IPV4_8_TABLE_ID = 8;
const bit<6>  IPV4_9_TABLE_ID = 9;
const bit<6>  IPV4_10_TABLE_ID = 10;
const bit<2>  IPV4_KEY_NUMBER = 1;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    bit<6>  tmpoffset;
    bit<2>  tmpmatchtype;
    bit<64> tmpkey;
}

struct headers {
    ethernet_t   ethernet;
    key_t        key;
    table_recv_t table_recv;
    table_send_t table_send;
    ipv4_t       ipv4;
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
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
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
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
    }

    table ipv4_1 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_1_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_2 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_2_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_3 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_3_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_4 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_4_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_5 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_5_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_6 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_6_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_7 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_7_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_8 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_8_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_9 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_9_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    table ipv4_10 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            tocpu;
        }
        size = 1024;
        default_action = tocpu(IPV4_10_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_1_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_1_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_1.apply();
            }
            
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_2_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_2_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_2.apply();
            }
            
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_3_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_3_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_3.apply();
            }
        
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_4_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_4_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_4.apply();
            }
        
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_5_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_5_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_5.apply();
            } 
        
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_6_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_6_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_6.apply();
            }
        
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_7_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_7_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_7.apply();
            }
           
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_8_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_8_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_8.apply();
            }    
        
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_9_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_9_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_9.apply();
            }
        
        if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_10_TABLE_ID && hdr.table_recv.lookUpResult == 0){drop();}
        else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv.isValid() && hdr.table_recv.tableId == IPV4_10_TABLE_ID && hdr.table_recv.lookUpResult == 1)){
            meta.tmpoffset = 32;
            meta.tmpmatchtype = 1;
            meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
            hdr.ethernet.etherType = TYPE_IPV4;
            ipv4_10.apply();
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
