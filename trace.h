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
#define MAC_STR_LEN 20
#define ARP_TAG 0x0608
#define ETH_OFFSET sizeof(struct eth_frame)

/* Fields are populated by reading raw frame data */
struct eth_frame{
   uint8_t dst[MAC_BYTES];
   uint8_t src[MAC_BYTES];
   uint16_t type;
} __attribute__((packed));


struct arp_frame{
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

/* Function declarations

*/



