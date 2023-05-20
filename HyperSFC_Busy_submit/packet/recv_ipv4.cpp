#include <iostream>

#include <vector>

#include "MyRawSocket.h"
#include "MyProtocol.h"

using namespace std;

int main()
{
    // Create a raw socket
    MyRawSocket my_raw_socket((unsigned char *)"eth0");
    unsigned char local_mac[6];
    my_raw_socket.GetMac(local_mac);

    // Import protocol
    MyProtocol my_protocol;

    // Initiate the receive buffer
    int mtu = 1500;
    unsigned char send_buffer[mtu] = {0};
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
        
        // Action: ipv4 (0x0800)
        if (recv_type.protocol[0] == (unsigned char)0x08 && recv_type.protocol[1] == (unsigned char)0x00)
        {
            cout<<"recv_ipv4"<<endl;
        }
        if (recv_type.protocol[0] == (unsigned char)0x08 && recv_type.protocol[1] == (unsigned char)0x01)
        {
            cout<<"recv_801"<<endl;
        }
    }
}
