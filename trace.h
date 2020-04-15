#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
/* For net address manipulation */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <endian.h>


#define MAC_BYTES 6
#define IP_HLEN_MULTI 4
/* These lengths have extra padding */
#define MAC_STR_LEN 20
#define IP_STR_LEN 20

#define ICMP_TAG 0x01
#define IP4_TAG 0x0800
#define VALID_IP_CHK 0
#define ARP_TAG 0x0806
#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
#define ICMP_REQ 0x08
#define ICMP_REP 0

#define ETH_LEN sizeof(struct eth_frame)
#define IP_LEN sizeof(struct eth_frame) + sizeof(struct ip4_header)


struct eth_frame{
   uint8_t dst[MAC_BYTES];
   uint8_t src[MAC_BYTES];
   uint16_t type;
} __attribute__((packed));


struct arp_header{
   uint16_t htype;
   uint16_t ptype;
   uint8_t hsize;
   uint8_t psize;
   uint16_t opcode;
   uint8_t src_mac[MAC_BYTES];
   uint32_t src_ip;
   uint8_t dest_mac[MAC_BYTES];
   uint32_t dest_ip;
} __attribute__ ((packed));


struct ip4_header{
   /* Version and header length each 4 bits */
   uint8_t version_hlen;
   uint8_t tos;
   uint16_t pdu_len;
   uint16_t id;
   /* flags + fragment offset */
   uint16_t flags_offset;
   uint8_t ttl;
   uint8_t protocol;
   uint16_t hchecksum;
   uint32_t src_ip;
   uint32_t dest_ip;
} __attribute__ ((packed));


/* Function declarations

*/



