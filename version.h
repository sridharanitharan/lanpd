
#include "sniffer.h"

void version_of_the_tool(){
drawing();
printf("ARP{address resolution protocol} spoof Detector v0.24\n");
}
void help_to_user(char *bin){
  printf("\n\t\t\t Available argument \n");
  printf("🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️\n");
  printf("-h or --help :\t\t show a help for the tool[HOW TO  USE]👁️‍🗨️ \n");
  printf("-i or --interface :\t provide a interface to sniff on it 🧑‍💻️\n");
  printf("-v or --version :\t show a version about the tool⚒️\n");
  printf("-l or --lookup :\t show a available interface[eg:eth0 ,wlan0]🖨️\n");
  printf("🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️🔹️");
  printf("\nUsage %s -i <interface> [you can look for the interface using -l or --lookup \n",bin);
}