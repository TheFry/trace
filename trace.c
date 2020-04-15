#include "trace.h"
#include "checksum.h"

/* Globals */
static pcap_t *file;
static struct pcap_pkthdr *hdr;
static const u_char *data;

void read_packets();
uint16_t parse_ether();
void parse_arp();
void get_mac_str(uint8_t *, char *);
void get_ip_str(uint32_t, char *);
void parse_ip4();

/* Parse args, open file, launch program */
int main(int argc, char **argv){
   char errbuf[PCAP_ERRBUF_SIZE];
   
   if(argc != 2){
      printf("Usage: trace TraceFile.pcap\n");
      exit(-1);
   }

   /* Open file */
   file = pcap_open_offline(argv[1], errbuf);

   if(file == NULL){
      printf("%s\n", errbuf);
      exit(-1);
   }

   read_packets();
   pcap_close(file);
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
      /* ARP payload */
      if(payload_t == ARP_TAG){
         parse_arp();
      
      /*IP Payload */
      }else if(payload_t == IP4_TAG){
         parse_ip4();
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

   /* ARP */
   if(ntohs(frame.type) == ARP_TAG){
      printf("\t\tType: ARP\n\n");
      return ARP_TAG;
   
   /* IP */
   }else if(ntohs(frame.type) == IP4_TAG){
      printf("\t\tType: IP\n\n");
      return IP4_TAG;
   }

   /* Other */
   printf("\t\tType: 0x%x\n", ntohs(frame.type)); 
   return -1;
}


/* Parse ARP header */
void parse_arp(){
   struct arp_header header;
   char mac_buff[MAC_STR_LEN]; /* String Buffer */
   char ip_buff[IP_STR_LEN];

   printf("\tARP header\n");

   /* Get arp header info from pcap file */
   memcpy(&header, data + ETH_LEN, sizeof(struct arp_header));

   /* Opcode: Convert to host and compare Request/Reply values*/
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


/* Parse IPv4 headers */
void parse_ip4(){
   struct ip4_header header;
   char ip_buff[IP_STR_LEN]; /* String Buffer */
   uintptr_t start_addr;
   unsigned short checksum = 0;
   int header_length = 0;

   printf("\tIP Header\n");

   start_addr = (uintptr_t)data + ETH_LEN;

   /* Get IPv4 data from pcap file */
   memcpy(&header, (void *)start_addr, sizeof(struct ip4_header));
   header_length = (header.version_hlen & 0x0F) * IP_HLEN_MULTI;

   printf("\t\tHeader Len: %d (bytes)\n",header_length);
   printf("\t\tTOS: 0x%X\n", header.tos);
   printf("\t\tTIL: %d\n", header.ttl);
   printf("\t\tIP PDU Len: %d (bytes)\n", ntohs(header.pdu_len));
   
   /* Check payload protocol */
   printf("\t\tProtocol: ");
   if(header.protocol == ICMP_TAG){
      printf("ICMP\n");
   }else{
      printf("0x%X\n", header.protocol);
   }
   
   /* Calculate/print Checksum */
   checksum = in_cksum((void *)start_addr, header_length);
   printf("\t\tCHKSUM: ");
   if(checksum == VALID_IP_CHK){
      printf("Correct ");
   }else{
      printf("Incorrect ");
   }
   printf("(0x%X)\n", header.hchecksum);

   /* IP addresses */
   get_ip_str(header.src_ip, ip_buff);
   printf("\t\tSender IP: %s\n", ip_buff);
   get_ip_str(header.dest_ip, ip_buff);
   printf("\t\tDest IP: %s\n", ip_buff);

   printf("\n");
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

   /* 0 out string */
   memset(str, 0, IP_STR_LEN);

   /* Put address into usable form */
   address.s_addr = (in_addr_t) value;

   /* Convert and return */
   temp = inet_ntoa(address);
   memcpy(str, temp, strlen(temp));
}