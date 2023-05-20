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

#define MAX_LABLE 64

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
    bit<6>  tmptablenum;
}

struct headers {
    ethernet_t   ethernet;
    table_recv_t[MAX_LABLE] table_recv;
    table_send_t table_info;
    table_send_t table1_send;
    key_t        key1_1;
    
    table_send_t table2_send;
    key_t        key2_1;
    
    table_send_t table3_send;
    key_t        key3_1;
    
    table_send_t table4_send;
    key_t        key4_1;
    
    table_send_t table5_send;
    key_t        key5_1;
    
    table_send_t table6_send;
    key_t        key6_1;
    
    table_send_t table7_send;
    key_t        key7_1;
    
    table_send_t table8_send;
    key_t        key8_1;
    
    table_send_t table9_send;
    key_t        key9_1;
    
    table_send_t table10_send;
    key_t        key10_1;
    
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
        packet.extract(hdr.table_recv.next);
        transition select(hdr.table_recv.last.bos) {
            1: parse_ipv4;
            0: parse_table_recv;
            default: accept;
        }
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
    
    action addtable1(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table1_send.setValid();
        hdr.table1_send.tableId = tableid;
        hdr.table1_send.keyNumber = keynumber;
        hdr.key1_1.setValid();
        hdr.key1_1.keyOffset = meta.tmpoffset;
        hdr.key1_1.matchType = meta.tmpmatchtype;
        hdr.key1_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable2(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table2_send.setValid();
        hdr.table2_send.tableId = tableid;
        hdr.table2_send.keyNumber = keynumber;
        hdr.key2_1.setValid();
        hdr.key2_1.keyOffset = meta.tmpoffset;
        hdr.key2_1.matchType = meta.tmpmatchtype;
        hdr.key2_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable3(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table3_send.setValid();
        hdr.table3_send.tableId = tableid;
        hdr.table3_send.keyNumber = keynumber;
        hdr.key3_1.setValid();
        hdr.key3_1.keyOffset = meta.tmpoffset;
        hdr.key3_1.matchType = meta.tmpmatchtype;
        hdr.key3_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable4(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table4_send.setValid();
        hdr.table4_send.tableId = tableid;
        hdr.table4_send.keyNumber = keynumber;
        hdr.key4_1.setValid();
        hdr.key4_1.keyOffset = meta.tmpoffset;
        hdr.key4_1.matchType = meta.tmpmatchtype;
        hdr.key4_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable5(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table5_send.setValid();
        hdr.table5_send.tableId = tableid;
        hdr.table5_send.keyNumber = keynumber;
        hdr.key5_1.setValid();
        hdr.key5_1.keyOffset = meta.tmpoffset;
        hdr.key5_1.matchType = meta.tmpmatchtype;
        hdr.key5_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable6(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table6_send.setValid();
        hdr.table6_send.tableId = tableid;
        hdr.table6_send.keyNumber = keynumber;
        hdr.key6_1.setValid();
        hdr.key6_1.keyOffset = meta.tmpoffset;
        hdr.key6_1.matchType = meta.tmpmatchtype;
        hdr.key6_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable7(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table7_send.setValid();
        hdr.table7_send.tableId = tableid;
        hdr.table7_send.keyNumber = keynumber;
        hdr.key7_1.setValid();
        hdr.key7_1.keyOffset = meta.tmpoffset;
        hdr.key7_1.matchType = meta.tmpmatchtype;
        hdr.key7_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable8(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table8_send.setValid();
        hdr.table8_send.tableId = tableid;
        hdr.table8_send.keyNumber = keynumber;
        hdr.key8_1.setValid();
        hdr.key8_1.keyOffset = meta.tmpoffset;
        hdr.key8_1.matchType = meta.tmpmatchtype;
        hdr.key8_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable9(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table9_send.setValid();
        hdr.table9_send.tableId = tableid;
        hdr.table9_send.keyNumber = keynumber;
        hdr.key9_1.setValid();
        hdr.key9_1.keyOffset = meta.tmpoffset;
        hdr.key9_1.matchType = meta.tmpmatchtype;
        hdr.key9_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action addtable10(bit<6> tableid, bit<2> keynumber) {
        hdr.ethernet.etherType = TOCPU_LOOKUP;
        standard_metadata.egress_spec = 2;
        hdr.table10_send.setValid();
        hdr.table10_send.tableId = tableid;
        hdr.table10_send.keyNumber = keynumber;
        hdr.key10_1.setValid();
        hdr.key10_1.keyOffset = meta.tmpoffset;
        hdr.key10_1.matchType = meta.tmpmatchtype;
        hdr.key10_1.keyData = meta.tmpkey;
        meta.tmptablenum = meta.tmptablenum + 1;
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
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
            addtable1;
        }
        size = 1024;
        default_action = addtable1(IPV4_1_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable2;
        }
        size = 1024;
        default_action = addtable2(IPV4_2_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable3;
        }
        size = 1024;
        default_action = addtable3(IPV4_3_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable4;
        }
        size = 1024;
        default_action = addtable4(IPV4_4_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable5;
        }
        size = 1024;
        default_action = addtable5(IPV4_5_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable6;
        }
        size = 1024;
        default_action = addtable6(IPV4_6_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable7;
        }
        size = 1024;
        default_action = addtable7(IPV4_7_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable8;
        }
        size = 1024;
        default_action = addtable8(IPV4_8_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable9;
        }
        size = 1024;
        default_action = addtable9(IPV4_9_TABLE_ID, IPV4_KEY_NUMBER);
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
            addtable10;
        }
        size = 1024;
        default_action = addtable10(IPV4_10_TABLE_ID, IPV4_KEY_NUMBER);
        //default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_1_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
            else if ((hdr.ethernet.etherType == TYPE_IPV4) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_1_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_1.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_2_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_2_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_2.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_3_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_3_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_3.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_4_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_4_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_4.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_5_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_5_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_5.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_6_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_6_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_6.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_7_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_7_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_7.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_8_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_8_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_8.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_9_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_9_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
                ipv4_9.apply();
           }
           
           if(hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_10_TABLE_ID && hdr.table_recv[0].lookUpResult == 0){drop();}
           else if ((hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TOCPU_LOOKUP) || (hdr.ethernet.etherType == TOCPU_RECV && hdr.table_recv[0].isValid() && hdr.table_recv[0].tableId == IPV4_10_TABLE_ID && hdr.table_recv[0].lookUpResult == 1)){
                if(hdr.table_recv[0].isValid()){hdr.table_recv.pop_front(1);}
                meta.tmpoffset = 32;
                meta.tmpmatchtype = 1;
                meta.tmpkey = (bit<64>)hdr.ipv4.dstAddr;
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
            hdr.table1_send.setInvalid();
            hdr.key1_1.setInvalid();
            
            hdr.table2_send.setInvalid();
            hdr.key2_1.setInvalid();
            
            hdr.table3_send.setInvalid();
            hdr.key3_1.setInvalid();
            
            hdr.table4_send.setInvalid();
            hdr.key4_1.setInvalid();
            
            hdr.table5_send.setInvalid();
            hdr.key5_1.setInvalid();
            
            hdr.table6_send.setInvalid();
            hdr.key6_1.setInvalid();
            
            hdr.table7_send.setInvalid();
            hdr.key7_1.setInvalid();
            
            hdr.table8_send.setInvalid();
            hdr.key8_1.setInvalid();
            
            hdr.table9_send.setInvalid();
            hdr.key9_1.setInvalid();
        
            hdr.table10_send.setInvalid();
            hdr.key10_1.setInvalid();
        }
        else if (hdr.ethernet.etherType == TOCPU_LOOKUP){
            hdr.table_info.setValid();
            hdr.table_info.tableId = meta.tmptablenum;
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
        packet.emit(hdr.table_info);
        packet.emit(hdr.table1_send);
        packet.emit(hdr.key1_1);
        
        packet.emit(hdr.table2_send);
        packet.emit(hdr.key2_1);
        
        packet.emit(hdr.table3_send);
        packet.emit(hdr.key3_1);
        
        packet.emit(hdr.table4_send);
        packet.emit(hdr.key4_1);
        
        packet.emit(hdr.table5_send);
        packet.emit(hdr.key5_1);
        
        packet.emit(hdr.table6_send);
        packet.emit(hdr.key6_1);
        
        packet.emit(hdr.table7_send);
        packet.emit(hdr.key7_1);
        
        packet.emit(hdr.table8_send);
        packet.emit(hdr.key8_1);
        
        packet.emit(hdr.table9_send);
        packet.emit(hdr.key9_1);
        
        packet.emit(hdr.table10_send);
        packet.emit(hdr.key10_1);
        
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
