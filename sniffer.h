
#ifndef SNIFFER_H
#define SNIFFER_H


#define ARP_RQ 1
#define ARP_RS 2
#include "get_ip_mac.h"
#include "arp_alert.h"
#include "interface.h"

void drawing(){
printf("          |\\___/|           \n");
printf("         =) ^Y^ (=            .    \n");          
printf("          \\  ^  /\n");
printf("           )=*=(       *@7h3_h4k3r\n");
printf("          /     \\ \n");
printf("          |     |\n");
printf("        /| | | |\\ \n");
printf("         \\| | |_|/\\ \n");
printf("  _/\\_//_// ___/\\_/\\_/\\_/\\_/\\_/\\_/\\_\n");
printf("  |  |  |  | \\_) |  |  |  |  |  |  |\n ");
printf(" |  |  |  |  |  |  |  |  |  |  |  |  \n");
printf("ARP SP00F D3TECTOR : BY ⚡SRIDHARANITHARAN \n");
printf("  |  |  |  |  |  |  |  |  |  |  |  |\n "); 
printf(" |  |  |  |  |  |  |  |  |  |  |  | \n ");

}

int sniff_start(char *device){

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr{
uint16_t htype;//hardware address == mac address
uint16_t ptype;//protocal type
uint8_t hlen;// herdware leganth
uint8_t plen;//protocal leganth
uint16_t operation;//operation its say about the arp request or responce
uint8_t sender_mac[6];//sender mac address leganth 
uint8_t sender_ip[4];// sender ip address leganth 
uint8_t target_mac[6];// target mac
uint8_t target_ip[4];// target ip
};
// THIS IS MAIN CODE OF THE PROJECT 

  pcap_t* pcap_devs;
  char error[PCAP_ERRBUF_SIZE];
  const __u_char *packet;
  struct pcap_pkthdr header;
  struct ether_header *eptr;
  time_t ct,lt;
  int long diff;
  int count = 0;
  arp_hdr *arpheader = NULL;
  char *s_mac,*s_ip,*target_mac,*target_ip;
  
  pcap_devs = pcap_open_live(device,BUFSIZ,1,1,error);
  if(pcap_devs == NULL){
    printf("ERROR %s " ,error);
    details_about_interface();
    }
    else{
      printf("listening on %s ...... \n",device);
      }
    while(1){
      packet = pcap_next(pcap_devs,&header);
      if(packet == NULL){
        printf("ERROR : cannot capture a packet ");
        return -1;
        }
        else{
        eptr = (struct ether_header*)packet;
        if(ntohs(eptr->ether_type) == ETHERTYPE_ARP){
        ct = time(NULL);
        diff = ct - lt;
        printf("current time %ld -> differ: %ld -> [COUNTER = %d]",ct,diff,count);
        if(diff > 20){
            count = 0;
            }
        arpheader = (arp_hdr*)(packet+14);
        printf("RECEIVE A ARP  PACKET WITH LEN:[%d]\n",header.len);
        printf("receive at %s\n",ctime((const time_t*) &header.ts.tv_sec));
        printf("Ether net header %d\n",ETHER_HDR_LEN);
        printf("OPERATION TYPE : %s\n",(ntohs(arpheader->operation) == ARP_RQ) ? "ARP REQUEST" : "ARP RESPONSE ");
        s_mac = get_mac(arpheader->sender_mac);
        s_ip = get_ip(arpheader->sender_ip);
        target_mac = get_mac(arpheader->target_mac);
        target_ip = get_ip(arpheader->target_ip);
        printf("SENDER MAC ADDRESS %s\n",s_mac);
        printf("SENDER IP ADDRESS %s\n",s_ip);
        printf("TARGET MAC ADDRESS %s\n",target_mac);
        printf("TARGET IP ADDRESS %s\n",target_ip);
        count++;
        lt = time(NULL);
        if(count>10){
              arp_spoof(s_ip,s_mac);
              }
         }
        }
      }
      return 0;
}
#endif /* SNIFFER_H */