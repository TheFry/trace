#include "trace.h"

/* Globals */
static pcap_t *file;
static struct pcap_pkthdr *hdr;
static const u_char *data;

void read_packets();
uint16_t parse_ether();
void parse_arp();
void get_mac_str(uint8_t *, char *);
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
   uint16_t payload_t;

   /* Get packet */
   retval = pcap_next_ex(file, &hdr, &data);
   
   /* While there are still packets, read */
   while(retval == 1){
      printf("Packet number: %d  Frame Len: %d\n\n", i, hdr->caplen);
      payload_t = parse_ether();

      /* Determine and retrieve payload */

      /* Increment and call */
      ++i;
      retval = pcap_next_ex(file, &hdr, &data);
   }

   /* If the loop was broken for an unknown issue, error and exit. */
   if(retval == PCAP_ERROR){
      perror("Error reading next packet");
      exit(-1);
   }
}


/* Read MAC addresses and return payload type */
uint16_t parse_ether(){
   struct ether_addr address;
   struct eth_frame frame;
   char buff[MAC_STR_LEN];

   printf("\tEthernet Header\n");
   memcpy(&frame, data, sizeof(struct eth_frame));
   get_mac_str(frame.dst, buff);
   printf("\t\tDest Mac: %s\n", buff);
   get_mac_str(frame.src, buff);
   printf("\t\tSource MAC: %s\n", buff);



   /* Type (only supports ARP right now) */
   if(frame.type == ARP_TAG){
      printf("\t\tType: ARP\n\n");
      return ARP_TAG;
   }else{
      printf("%x\n", frame.type); 
   }
   return -1;
}

void get_mac_str(uint8_t *value, char str[MAC_STR_LEN]){
   struct ether_addr address;
   char *temp;
   
   memset(str, 0, MAC_STR_LEN);
   memcpy(address.ether_addr_octet, value, MAC_BYTES);
   temp = ether_ntoa(&address); 
   memcpy(str, temp, strlen(temp));
}

/*
void parse_arp(){
   struct arp_frame frame;
   memcpy(&frame, data + ETH_OFFSET, sizeof(struct arp_frame));

   Src 
   memcpy(address.ether_addr_octet, frame.src_mac, MAC_BYTES);
   printf("\t\tSender MAC: %s\n", ether_ntoa(&address)); 

   Dest 
   memcpy(address.ether_addr_octet, frame.destclea_mac, MAC_BYTES);
   printf("\t\tTarget MAC: %s\n", ether_ntoa(&address)); 
}
*/

