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
uint16_t parse_ip4(int *);
void parse_icmp();
void parse_tcp();


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
   int retval = 0;
   int i = 1;
   uint16_t payload_t;
   int len = 0;         /* Length of IP header */

   /* Get packet */
   retval = pcap_next_ex(file, &hdr, &data);
   
   /* While there are still packets, read */
   while(retval == 1){
      printf("\nPacket number: %u  Frame Len: %u\n\n", i, hdr->caplen);
      payload_t = parse_ether();
      /* ARP payload */
      if(payload_t == ARP_TAG){
         parse_arp();
      
      /*IP Payload */
      }else if(payload_t == IP4_TAG){
         payload_t = parse_ip4(&len);
         if(payload_t == ICMP_TAG){
            parse_icmp(len);
         }else if(payload_t == TCP_TAG){
            parse_tcp(len);
         }
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


/* Parse IPv4 headers */
uint16_t parse_ip4(int *len){
   struct ip4_header header;
   char ip_buff[IP_STR_LEN]; /* String Buffer */
   uintptr_t start_addr;
   unsigned short checksum = 0;
   int header_length = 0;
   uint16_t retval = 0;

   printf("\tIP Header\n");

   start_addr = (uintptr_t)data + ETH_LEN;

   /* Get IPv4 data from pcap file */
   memcpy(&header, (void *)start_addr, sizeof(struct ip4_header));
   
   /* Calculate header length and set return argument */
   header_length = (header.version_hlen & 0x0F) * IP_HLEN_MULTI;
   *len = header_length;

   /* Print basic info */
   printf("\t\tHeader Len: %u (bytes)\n",header_length);
   printf("\t\tTOS: 0x%x\n", header.tos);
   printf("\t\tTTL: %u\n", header.ttl);
   printf("\t\tIP PDU Len: %u (bytes)\n", ntohs(header.pdu_len));
   
   /* Check payload protocol */
   printf("\t\tProtocol: ");
   if(header.protocol == ICMP_TAG){
      printf("ICMP\n");
      retval = ICMP_TAG;
   }else if(header.protocol == TCP_TAG){
      printf("TCP\n");
      retval = TCP_TAG;
   }else{
      printf("Unknown\n");
   }
   
   /* Calculate/print Checksum */
   checksum = in_cksum((void *)start_addr, header_length);
   printf("\t\tChecksum: ");
   if(checksum == VALID_IP_CHK){
      printf("Correct ");
   }else{
      printf("Incorrect ");
   }
   printf("(0x%x)\n", header.hchecksum);

   /* IP addresses */
   get_ip_str(header.src_ip, ip_buff);
   printf("\t\tSender IP: %s\n", ip_buff);
   get_ip_str(header.dest_ip, ip_buff);
   printf("\t\tDest IP: %s\n", ip_buff);

   printf("\n");
   return retval;
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


/* Parse ICMP */
void parse_icmp(int ip_len){
   uint8_t type = 0;
   printf("\tICMP Header\n");
   memcpy(&type, data + ETH_LEN + ip_len, sizeof(uint8_t));
   printf("\t\tType: ");
   if(type == ICMP_REQ){
      printf("Request\n\n");
   }else if(type == ICMP_REP){
      printf("Reply\n\n");
   }else{
      printf("%u\n\n", type);
   }
}


void parse_tcp(int ip_len){
   struct tcp_header header;
   uint16_t h_order = 0;
   uint8_t hlen = 0;

   memcpy(&header, data + ETH_LEN + ip_len, sizeof(struct tcp_header));

   printf("\tTCP Header:\n");
   printf("\t\tSource Port: : %u\n", ntohs(header.src_port));
   printf("\t\tDest Port: : %u\n", ntohs(header.dst_port));
   printf("\t\tSequence Number: %u\n", ntohl(header.seq_num));

   /* Load offset/flag bits into h_order.
    * Conver to host order */
   h_order = ntohs(header.hlen_flags);

   /* Get header length/offset bits */
   hlen = (h_order & 0xF000) >> 12;

   /* Print ACK num/flag */
   printf("\t\tACK Number: ");
   if((h_order & 0x0010) >> 4 == 0x0001){
      printf("%u\n\t\tACK Flag: Yes\n", header.ack_num);
   }else{
      printf("<not valid>\n\t\tACK Flag: No\n");
   }

   /* SYN Flag */
   printf("\t\tSYN Flag: ");
   if(((h_order >> 1) & 0x0001) == 0x0001){printf("Yes\n");}
   else{printf("No\n");}

   /* RST flag */
   printf("\t\tRST Flag: ");
   if(((h_order >> 2) & 0x0001) == 0x0001){printf("Yes\n");}
   else{printf("No\n");}

   /* FIN flag */
   printf("\t\tFIN Flag: ");
   if((h_order & 0x0001) == 0x0001){printf("Yes\n");}
   else{printf("No\n");}

   /* Window Size */
   printf("\t\tWindow Size: %u\n\n", ntohs(header.window_size));
}

/*
void tcp_check(struct tcp_header tcp){
   struct ip_header ip;

}
*/


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