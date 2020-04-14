#include "trace.h"

/* Globals */
static pcap_t *file;
static struct pcap_pkthdr *hdr;
static const u_char *data;

void read_packets();
uint16_t parse_ether();
void parse_arp();
void get_mac_str(uint8_t *, char *);
void get_ip_str(uint32_t, char *);

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
 * This is where the main loop is executed 
 */
void read_packets(){
   /* Error check and interator */
   int retval = 0;
   int i = 1;
   uint16_t payload_t;

   /* Get packet */
   retval = pcap_next_ex(file, &hdr, &data);
   
   /* While there are still packets, read */
   while(retval == 1){
      printf("\nPacket number: %d  Frame Len: %d\n\n", i, hdr->caplen);
      payload_t = parse_ether();

      /* Determine and retrieve payload */
      if(payload_t == ARP_TAG){
         parse_arp();
      }
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


/* Read Ethernet Frame and print associate data 
 * Return the type of the next header
 */
uint16_t parse_ether(){
   struct eth_frame frame;
   char buff[MAC_STR_LEN]; /* String Buffer */

   printf("\tEthernet Header\n");

   /* Get frame from pcap file */
   memcpy(&frame, data, sizeof(struct eth_frame));

   /* Call get_mac string and print for each address */
   get_mac_str(frame.dst, buff);
   printf("\t\tDest MAC: %s\n", buff);
   get_mac_str(frame.src, buff);
   printf("\t\tSource MAC: %s\n", buff);

   /* Print and return type field */
   if(frame.type == ARP_TAG){
      printf("\t\tType: ARP\n\n");
      return ARP_TAG;
   }else{
      printf("Type: 0x%x\n", frame.type); 
   }
   return -1;
}


/* Take a 6 byte array MAC (value) and convert it
 * to a printable string 
 */
void get_mac_str(uint8_t *value, char str[MAC_STR_LEN]){
   struct ether_addr address;
   char *temp;
   
   /* 0 out return string */
   memset(str, 0, MAC_STR_LEN);

   /* Put address into a usable form for ether_ntoa() */
   memcpy(address.ether_addr_octet, value, MAC_BYTES);
   
   /* Convert and return */
   temp = ether_ntoa(&address); 
   memcpy(str, temp, strlen(temp));
}


/* Take a uint32_t ip value and convert it
 * to a printable string 
 */
void get_ip_str(uint32_t value, char str[IP_STR_LEN]){
   char *temp;
   struct in_addr address;

   memset(str, 0, IP_STR_LEN);
   address.s_addr = (in_addr_t) value;
   temp = inet_ntoa(address);
   memcpy(str, temp, strlen(temp));
}

/* Parse ARP header */
void parse_arp(){
   struct arp_header header;
   char mac_buff[MAC_STR_LEN]; /* String Buffer */
   char ip_buff[IP_STR_LEN];

   printf("\tARP header\n");

   /* Get arp header info from pcap file */
   memcpy(&header, data + ETH_LEN, sizeof(struct arp_header));

   /* Opcode: Conver to host and compare Request/Reply values*/
   printf("\t\tOpcode: ");
   if(ntohs(header.opcode) == ARP_REQUEST){
      printf("Request\n");
   }else if(ntohs(header.opcode) == ARP_REPLY){
      printf("Reply\n");
   }else{
      printf("0x%X Unknown\n", ntohs(header.opcode));
   }

   /* Sender Info*/
   get_mac_str(header.src_mac, mac_buff);
   printf("\t\tSender MAC: %s\n", mac_buff);
   get_ip_str(header.src_ip, ip_buff);
   printf("\t\tSender IP: %s\n", ip_buff);

   /* Target Info*/
   get_mac_str(header.dest_mac, mac_buff);
   printf("\t\tTarget MAC: %s\n", mac_buff);
   get_ip_str(header.dest_ip, ip_buff);
   printf("\t\tTarget IP: %s\n", ip_buff);
   printf("\n"); 
}


