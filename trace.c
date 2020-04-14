#include "trace.h"

/* Globals */
static pcap_t *file;
static struct pcap_pkthdr *hdr;
static const u_char *data;

void read_packets();
void parse_ether();


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


/* Search Packets for headers 
   This is where the main loop is executed */
void read_packets(){
   /* Error check and interator */
   int retval = 0;
   int i = 1;

   /* Get packet */
   retval = pcap_next_ex(file, &hdr, &data);
   
   /* While there are still packets, read */
   while(retval == 1){
      printf("Packet number: %d  Frame Len: %d\n\n", i, hdr->caplen);
      parse_ether();
      ++i;
      retval = pcap_next_ex(file, &hdr, &data);
   }

   /* If the loop was broken for an unknown issue, error and exit. */
   if(retval == PCAP_ERROR){
      perror("Error reading next packet");
      exit(-1);
   }
}


/* Read MAC addresses and print */
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
