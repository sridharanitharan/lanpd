#ifndef ARP_ALERT_H
#define ARP_ALERT_H


//in this function about alert id the user arp poision detected 
int arp_spoof(char* ip,char* mac){
  printf("ATTACKER IP[%s]_AND_MAC[%s]\n",ip,mac);
  for(int i=0;i<5;i++){
      printf("ARP spoof detector [secure your network system immediately]");
      }
}
#endif
