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

/* Number of 16bit integers in MAC */
#define MAC_16_SIZE 3
struct eth_frame{
   uint16_t dst[MAC_16_SIZE];
   uint16_t src[MAC_16_SIZE];
   uint16_t type;
} __attribute__((packed));

void parse_ether();
void print_ether(struct eth_frame);


int main(int argc, char **argv){
   parse_ether();
   return 0;
}


void parse_ether(){
   char errbuf[PCAP_ERRBUF_SIZE];
   struct pcap_pkthdr *hdr;
   const u_char *data;
   struct eth_frame frame;


   /* Open file */
   pcap_t *file = pcap_open_offline("./given/arp/ArpTest.pcap", errbuf);

   if(file == NULL){
      printf("%s\n", errbuf);
      exit(-1);
   }

   if(pcap_next_ex(file, &hdr, &data) == PCAP_ERROR){
      perror("Pcap read issue");
   }

   printf("Length of packet: %d\n", hdr->caplen);


   memcpy(&frame, data, 14);
   print_ether(frame);
}


void print_ether(struct eth_frame frame){
   uint16_t current = 0;
   int i = 0;
   /* Print Src */
   for(i = 0; i < MAC_16_SIZE; i++){
      memcpy(&current, frame.dst[i], sizeof(uint16_t));
      current = ntohs(current);
      
   }

   
}
