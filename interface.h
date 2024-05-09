#ifndef INTERFACE_H
#define INTERFACE_H

// in this funcution about the interface (eg eth0)
int details_about_interface(){
  char error[PCAP_ERRBUF_SIZE];
  pcap_if_t *interface,*temp;
  int i =0;
  if(pcap_findalldevs(&interface,error) == -1){
    printf("ERROR :  DEVICE NOT FOUND");
    }
  else{
  printf("AVAILABLE DEVICES{interface} are :\n");
  for(temp= interface;temp;temp = temp->next){
      printf("{%d}_[%s]\n",++i,temp->name);
    }
  }
}
#endif