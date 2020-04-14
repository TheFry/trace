#include "trace.h"
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
struct eth_frame{
   uint8_t dst[MAC_BYTES];
   uint8_t src[MAC_BYTES];
   uint16_t type;
} __attribute__((packed));

void parse_ether();
void print_ether(struct eth_frame);
void read_packets();

/* Globals */
static pcap_t *file;
static struct pcap_pkthdr *hdr;
static const u_char *data;

/* Parse args, open file, launch program */
int main(int argc, char **argv){
   char errbuf[PCAP_ERRBUF_SIZE];
   /* Open file */
   file = pcap_open_offline("./given/arp/ArpTest.pcap", errbuf);

   if(file == NULL){
      printf("%s\n", errbuf);
      exit(-1);
   }

   read_packets();
   return 0;
}


/*Search Packets for headers */
void read_packets(){
   int retval = 0;
   int i = 1;

   retval = pcap_next_ex(file, &hdr, &data);
   
   while(retval == 1){
      printf("Packet number: %d  Frame Len: %d\n\n", i, hdr->caplen);
      parse_ether();
      ++i;
      retval = pcap_next_ex(file, &hdr, &data);
   }

   if(retval == PCAP_ERROR){
      perror("Error reading next packet");
      exit(-1);
   }
}


void parse_ether(){
   struct ether_addr address;
   struct eth_frame frame;

   printf("\tEthernet Header\n");
   memcpy(&frame, data, sizeof(struct eth_frame));

   /* Dest */
   memcpy(address.ether_addr_octet, frame.dst, MAC_BYTES);
   printf("\t\tDest MAC: %s\n", ether_ntoa(&address)); 

   /* Src */
   memcpy(address.ether_addr_octet, frame.src, MAC_BYTES);
   printf("\t\tSource MAC: %s\n\n\n", ether_ntoa(&address)); 
}
