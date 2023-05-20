#include <iostream>
#include <fstream>
#include <vector>
#include <hiredis/hiredis.h>

#include "MyRawSocket.h"
#include "MyProtocol.h"
#include <math.h>

using namespace std;

vector <string> split(string str){
    vector <string> result;
    string delim = ",";
    size_t pos = str.find(delim);
    string tmp = str.substr(0,pos);
    str = str.substr(pos+1,str.size());
    result.push_back(tmp);
    pos = str.find(delim);
    while (pos !=str.npos){
        str = str.replace(pos,1," ");
        pos = str.find(delim);
    }
    result.push_back(str);
    return result;
}

void genCommand(string table_name, string action_name,char* keydata, int keyoffset, string param)
{
    ofstream ofs;
    ofs.open("s1.txt",ios::out);
    ofs<<"table_add "<<table_name<<" "<<action_name<<" "<<keydata<<"/"<<keyoffset<<" => "<<param<<endl;
    ofs.close();
}


int main()
{   
    //Table map and matchtype:1.lpm 2.exact 3.ternary
    const char* table[] ={
    "Table_name",
    "MyIngress.ipv4_1",
    "MyIngress.ipv4_2",
    "MyIngress.ipv4_3",
    "MyIngress.ipv4_4",
    "MyIngress.ipv4_5",
    "MyIngress.ipv4_6",
    "MyIngress.ipv4_7",
    "MyIngress.ipv4_8",
    "MyIngress.ipv4_9",
    "MyIngress.ipv4_10"
    };
    
    // Create a redis connect
    redisContext *conn  = redisConnectUnix("/var/run/redis/redis-server.sock");
    if(conn != NULL && conn->err)
    {printf("connection error: %s\n",conn->errstr);return 0;}
    
    // Create a raw socket
    MyRawSocket my_raw_socket((unsigned char *)"eth0");
    unsigned char local_mac[6];
    my_raw_socket.GetMac(local_mac);

    // Import protocol
    MyProtocol my_protocol;

    // Initiate the receive buffer
    int mtu = 1500;
    unsigned char recv_buffer[mtu] = {0};

    // Start receiving
    while (true)
    {
        int recv_packet_length = my_raw_socket.RecvPacket(recv_buffer, sizeof(recv_buffer));

        int send_index = 0;
        int recv_index = 0;

        // Filter: Length > 14 (has Ethernet)
        if (recv_packet_length < 14)
        {
            continue;
        }

        // Parser: H_ETHERNET
        struct H_ETHERNET recv_ethernet = my_protocol.GetEthernet(recv_buffer, recv_index);
        recv_index += sizeof(recv_ethernet);
        
        // Filter: Get packets which are not sent from local
        if (local_mac[0] == recv_ethernet.src_mac[0] && local_mac[1] == recv_ethernet.src_mac[1] &&
            local_mac[2] == recv_ethernet.src_mac[2] && local_mac[3] == recv_ethernet.src_mac[3] &&
            local_mac[4] == recv_ethernet.src_mac[4] && local_mac[5] == recv_ethernet.src_mac[5])
        {
            continue;
        }

        // Parser: H_TYPE
        struct H_TYPE recv_type = my_protocol.GetType(recv_buffer, recv_index);
        recv_index += sizeof(recv_type);

        // Parser: H_TABLE
        struct H_TABLE recv_table = my_protocol.GetTable(recv_buffer, recv_index);
        recv_index += sizeof(recv_table);
        
        // Parser: H_KEY
        struct H_KEY recv_key = my_protocol.GetKey(recv_buffer, recv_index);
        recv_index += sizeof(recv_key);
        
        // Action: table_miss (0x0801)
        if (recv_type.protocol[0] == (unsigned char)0x08 && recv_type.protocol[1] == (unsigned char)0x01)
        {
            // Parser: Table info
            cout<<"recv_table_miss"<<endl;
            int keynumber_length = 2;
            int keyoffset_length = 6;
            int tableid = recv_table.tableinfo[0]>>keynumber_length;
            int keynumber = recv_table.tableinfo[0] - tableid*keynumber_length*2;
            cout<<"tableid:"<<tableid<<endl;
            cout<<"keynumber:"<<keynumber<<endl;
            int keyoffset = recv_key.keyinfo[0]>>(8-keyoffset_length);
            cout<<"keyoffset:"<<keyoffset<<endl;
            char keydata[128] = {0};
            int key_index = 0;
            for(int i=(64-keyoffset)/8;i<8;i++){
                int keyd = recv_key.keydata[i];
                if(i==7){key_index += sprintf(keydata+key_index,"%d",keyd);}
                else{key_index += sprintf(keydata+key_index,"%d.",keyd);}
            }
            cout<<keydata<<endl;
            //Lookup in Redis
            redisReply *reply = (redisReply*)redisCommand(conn,"get %s",keydata);
            if(reply->len==0){
                cout<<"miss again"<<endl;
                recv_table.tableinfo[0] = tableid*4;
            }
            else{
                printf("%s\n",reply->str);
                string s = reply->str;
                vector <string> result = split(s);
                //Generate table_add command
                genCommand(table[tableid], result[0], keydata, keyoffset, result[1]);
                recv_table.tableinfo[0] = tableid*4 + 2;
            }
            freeReplyObject(reply); 
            //sendback
            recv_buffer[13] = recv_buffer[13]+2; //0x803
            recv_buffer[14] = recv_table.tableinfo[0];
            int send_packet_length = recv_packet_length-9;
            for(int j=15;j<send_packet_length;j++){
                recv_buffer[j] = recv_buffer[j+9];
            }
            my_raw_socket.SendPacket(recv_buffer, send_packet_length);
            cout<<"sendback"<<endl;
            }
        }
        redisFree(conn);
        return 0;
}
