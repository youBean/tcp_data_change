#pragma once
#include <stdint.h>
#include <string.h>
#include <map>

using namespace std;

#pragma pack(push,1)
typedef struct Pseudoheader{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved = 0;
    uint8_t protocol;
    uint16_t tcp_Len;
}pseudo_header;
typedef struct IP{
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
}IP;
typedef struct TCP{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
    uint8_t options[12];
}TCP;
typedef struct packet{
    IP ip;
    TCP tcp;
}Packet;
#pragma pack(pop)

typedef struct MAC{
    uint8_t mac[6];
    bool operator <(const MAC& var) const
    {
        return memcmp(mac, var.mac, sizeof(mac)) < 0;
    }
}MAC;

typedef struct Key{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    bool operator <(const Key& var) const
    {
        if(src_ip != var.src_ip){
            return src_ip < var.src_ip;
        }else if(dst_ip != var.dst_ip){
            return dst_ip < var.dst_ip;
        }else if(src_port != var.src_port){
            return src_port < var.src_port;
        }else{
            return dst_port < var.dst_port;
        }
    }
}Key;
