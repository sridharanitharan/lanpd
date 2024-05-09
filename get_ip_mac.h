#ifndef GET_IP_MAC_H
#define GET_IP_MAC_H

char* get_mac(uint8_t mac[6]){
    char *m = (char*)malloc(20*sizeof(char));
    sprintf(m,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return m;
}
char* get_ip(uint8_t ip[4]){
    char *m = (char*)malloc(20*sizeof(char));
    sprintf(m,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
    return m;
}
#endif