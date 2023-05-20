#ifndef MYPROTOCOL_H
#define MYPROTOCOL_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Header define

struct H_ETHERNET
{
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
};

struct H_TYPE
{
    unsigned char protocol[2];  //0x801 table_miss, 0x800 IPV4
};

struct H_TABLE
{
    unsigned char tableinfo[1]; 
};

struct H_KEY
{
    unsigned char keyinfo[1];
    unsigned char keydata[8];
};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class MyProtocol
{
public:
    int SetEthernet(unsigned char *buffer, int index,
                    const unsigned char *dst_mac, int dst_mac_length,
                    const unsigned char *src_mac, int src_mac_length);
    int SetType(unsigned char *buffer, int index,
                const unsigned char *protocol, int protocol_length);
    int SetTable(unsigned char *buffer, int index,
                    const unsigned char *tableinfo, int tableinfo_length);
    int SetKey(unsigned char *buffer, int index,
                    const unsigned char *keyinfo, int keyinfo_length,
                    const unsigned char *keydata, int keydata_length);

    struct H_ETHERNET GetEthernet(unsigned char *buffer, int index);
    struct H_TYPE GetType(unsigned char *buffer, int index);
    struct H_TABLE GetTable(unsigned char *buffer, int index);
    struct H_KEY GetKey(unsigned char *buffer, int index);
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int MyProtocol::SetEthernet(unsigned char *buffer, int index,
                            const unsigned char *dst_mac, int dst_mac_length,
                            const unsigned char *src_mac, int src_mac_length)
{
    for (int i = 0; i < dst_mac_length; i++)
    {
        buffer[index++] = dst_mac[i];
    }

    for (int i = 0; i < src_mac_length; i++)
    {
        buffer[index++] = src_mac[i];
    }

    return index;
}

int MyProtocol::SetType(unsigned char *buffer, int index,
                        const unsigned char *protocol, int protocol_length)
{
    for (int i = 0; i < protocol_length; i++)
    {
        buffer[index++] = protocol[i];
    }

    return index;
}

int MyProtocol::SetTable(unsigned char *buffer, int index,
                    const unsigned char *tableinfo, int tableinfo_length)
{
    for (int i = 0; i < tableinfo_length; i++)
    {
        buffer[index++] = tableinfo[i];
    }

    return index;
}

int MyProtocol::SetKey(unsigned char *buffer, int index,
                    const unsigned char *keyinfo, int keyinfo_length,
                    const unsigned char *keydata, int keydata_length)
{
    for (int i = 0; i < keyinfo_length; i++)
    {
        buffer[index++] = keyinfo[i];
    }
    for (int i = 0; i < keydata_length; i++)
    {
        buffer[index++] = keydata[i];
    }
    
    return index;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct H_ETHERNET MyProtocol::GetEthernet(unsigned char *buffer, int index)
{
    struct H_ETHERNET ethernet = {};

    for (int i = 0; i < sizeof(ethernet.dst_mac); i++)
    {
        ethernet.dst_mac[i] = buffer[index++];
    }

    for (int i = 0; i < sizeof(ethernet.src_mac); i++)
    {
        ethernet.src_mac[i] = buffer[index++];
    }

    return ethernet;
}

struct H_TYPE MyProtocol::GetType(unsigned char *buffer, int index)
{
    struct H_TYPE type = {};

    for (int i = 0; i < sizeof(type.protocol); i++)
    {
        type.protocol[i] = buffer[index++];
    }

    return type;
}

struct H_TABLE MyProtocol::GetTable(unsigned char *buffer, int index)
{
    struct H_TABLE t = {};

    for (int i = 0; i < sizeof(t.tableinfo); i++)
    {
        t.tableinfo[i] = buffer[index++];
    }

    return t;
}

struct H_KEY MyProtocol::GetKey(unsigned char *buffer, int index)
{
    struct H_KEY k = {};

    for (int i = 0; i < sizeof(k.keyinfo); i++)
    {
        k.keyinfo[i] = buffer[index++];
    }
    for (int i = 0; i < sizeof(k.keydata); i++)
    {
        k.keydata[i] = buffer[index++];
    }

    return k;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif
