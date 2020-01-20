#pragma once
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <map>

const static char * from_str;
const static char * to_str;
static unsigned char * send_data;
static uint32_t send_size;
static bool check_data_changed = false;
map<Key, unsigned int> m;

void usage(){
    printf("usage   : tcp_data_change <from string> <to string>\n");
    printf("example : tcp_data_change hacking HOOKING\n");
}
void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

uint16_t calc(void * real_data, unsigned int size) {
    char * data = (char *)real_data;
    uint32_t sum = 0xffff;
    for (unsigned int i = 0; i+1 < size; i += 2) {
        uint16_t word;
        memcpy(&word,data+i, 2);
        sum += ntohs(word);
        if (sum > 0xffff) {
            sum -= 0xffff;
        }
    }
    if (size & 1) {
        uint16_t word = 0;
        memcpy(&word,data+size-1, 1);
        sum += ntohs(word);
        if (sum > 0xffff) {
            sum -= 0xffff;
        }
    }
    return htons(~sum);
}

void check_flow(unsigned char * data, int size){
    Packet *packet = (Packet *)data;
    map<Key, unsigned int>::iterator iter;
    Key key, key2;
    key.src_ip = packet->ip.src_ip;
    key.src_port = packet->tcp.src_port;
    key.dst_ip = packet->ip.dst_ip;
    key.dst_port = packet->tcp.dst_port;

    key2.src_ip = packet->ip.dst_ip;
    key2.src_port = packet->tcp.dst_port;
    key2.dst_ip = packet->ip.src_ip;
    key2.dst_port = packet->tcp.src_port;
    iter = m.begin();
    if ( (iter = m.find(key)) != m.end()){
        //packet->tcp.seq = packet->tcp.seq + iter->second;
        packet->tcp.ack = packet->tcp.ack + iter->second;
    }
    iter = m.begin();
    if ( (iter = m.find(key2)) != m.end()){
        packet->tcp.seq = packet->tcp.seq - iter->second;
        //packet->tcp.ack = htons(ntohs(packet->tcp.ack) + iter->second);
    }
}

void data_change(unsigned char * data, int size){
    Packet *packet = (Packet *)data;
    uint8_t ihl = (packet->ip.v_l & 0xF) * 4;
    uint8_t tcp_l = (packet->tcp.offset_reserved >> 4) * 4;
    int distance = (strlen(to_str) - strlen(from_str));
    check_data_changed = false;
    
    // data field
    char * real_data = (char *)(data + ihl + tcp_l);
    string tmp_str(real_data);
    int times = 0;

    if(size > (ihl + tcp_l)){ // if HTTP data is exist
        int pos = 0, tmp;
        while((tmp = tmp_str.find(from_str, pos)) != string::npos){
            printf("\n[+] Find string \" %s \"\n", from_str);
            printf("\ntest1\n");
            tmp_str.erase(tmp, strlen(from_str)); 
            tmp_str.insert(tmp, to_str);
            if(distance > 0){
                times++; 
            }
            check_data_changed = true;
            pos += strlen(to_str);
        }
        strncpy(real_data, tmp_str.c_str(), tmp_str.length()); 
        pos = 0;
        tmp = 0;
        if(check_data_changed == true){
            if(distance > 0){ //change content length 
                char * cont_len = "Content-Length: "; 
                pos = tmp_str.find(cont_len) + strlen(cont_len);
                int changed_len;
                if(times > 0){
                    changed_len = atoi(&tmp_str[pos]) + (distance * times);
                }else{
                    changed_len = atoi(&tmp_str[pos]) + distance;
                } 
                char * temp = (char *)malloc(changed_len);
                sprintf(temp, "%d", changed_len);
                tmp_str.erase(pos);
                tmp_str.insert(pos, temp);
                strncpy(real_data, tmp_str.c_str(), tmp_str.length());

                Key key;
                key.src_ip = packet->ip.src_ip;
                key.src_port = packet->tcp.src_port;
                key.dst_ip = packet->ip.dst_ip;
                key.dst_port = packet->tcp.dst_port;
                m.insert(pair<Key, unsigned int>(key, changed_len-atoi(&tmp_str[pos])));

                check_flow(data, size);
            }
            if(times > 0){
                size += (distance * times);
            }else{
                size += distance;
            }

            // Calculate TCP/IP checksum
            packet->ip.checksum = 0;
            packet->ip.total_len += distance;
            packet->ip.checksum = calc(data, ihl);

            void * pseudo_data = (void *)malloc(sizeof(pseudo_header)+sizeof(uint8_t)*(size-ihl));
            pseudo_header * ph = (pseudo_header *)malloc(sizeof(pseudo_header));
            ph->src_ip= packet->ip.src_ip;
            ph->dst_ip = packet->ip.dst_ip;
            ph->protocol = packet->ip.protocol;
            ph->tcp_Len = htons(size - ihl);

            packet->tcp.checksum = 0;

            memcpy(pseudo_data, ph, sizeof(pseudo_header));
            memcpy(pseudo_data + sizeof(pseudo_header), data + ihl, sizeof(TCP));
            memcpy(pseudo_data + sizeof(pseudo_header) + sizeof(TCP), data + ihl + tcp_l, size-ihl-tcp_l);
            
            packet->tcp.checksum = calc(pseudo_data, sizeof(pseudo_header) + (size-ihl));

            send_data = data;
            send_size = size;

        }
    }
}

static u_int32_t print_pkt (struct nfq_data *tb){
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

		ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}
	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}
	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);
	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);
	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
	ret = nfq_get_payload(tb, &data); //data = packet
	if (ret >= 0)
		printf("payload_len=%d ", ret);

    check_flow(data, ret);
	data_change(data, ret);

    dump(data, ret);
    
	fputc('\n', stdout);
	return id;
}
	
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
    if(check_data_changed == true){
        return nfq_set_verdict(qh, id, NF_ACCEPT, send_size, send_data);
    }else{
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); // ACCEPT
    }
}

void init(char * from, char * to){
    from_str = (char *)from;
    to_str = (char *)to;
}
