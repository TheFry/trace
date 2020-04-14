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

/* Number of bytes for MAC address*/
#define MAC_BYTES 6

/* Fields are populated by reading raw frame data */
struct eth_frame{
   uint8_t dst[MAC_BYTES];
   uint8_t src[MAC_BYTES];
   uint16_t type;
} __attribute__((packed));

/* Function declarations
void read_packets();
void parse_ether();
*/



