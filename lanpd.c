// #include <stdio.h> // 
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h> // For usleep function
#include <pcap.h>
#include <error.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "version.h"
#include "sniffer.h"
#include "get_ip_mac.h"
#include "interface.h"

char* calculate_checksum(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        printf("Error: Failed to open file %s\n", filename);
        return NULL;
    }

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);

    while (1) {
        unsigned char buffer[4096];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer), f);
        if (bytes_read == 0) break;
        EVP_DigestUpdate(mdctx, buffer, bytes_read);

        // Introduce a delay of 100 milliseconds (100000 microseconds)
        usleep(100000);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);

    char* hex_digest = malloc((hash_len * 2) + 1);
    if (hex_digest == NULL) {
        fclose(f);
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    for (int i = 0; i < hash_len; i++) {
        sprintf(hex_digest + (i * 2), "%02x", hash[i]);
    }
    hex_digest[hash_len * 2] = '\0';

    fclose(f);
    EVP_MD_CTX_free(mdctx);
    return hex_digest;
}

void verify_integrity() {
    char* expected_checksum = "ed75c03a3c7a9201a96744ba9875655565794254211bbb4beed3f2dcd485e6f6";
    char* current_checksum = calculate_checksum("sniffer.h");
    if (current_checksum == NULL) {
        exit(1);
    }

    if (strcmp(current_checksum, expected_checksum) != 0) {
        printf("Error: Code has been modified. Execution halted.\n");
        exit(1);
    }

    free(current_checksum);
}

int main(int argc , char *argv[]){
    verify_integrity();
    printf("Code integrity verified. Proceeding with execution.\n");

    if(argc<2 || strcmp("-h",argv[1])==0 || strcmp("--help",argv[1])==0){
        version_of_the_tool();
        help_to_user(argv[0]);
        
    }
    else if(strcmp("-l",argv[1])==0 || strcmp("--lookup",argv[1])==0){
          details_about_interface();
          }
    else if(strcmp("-v",argv[1])==0 || strcmp("--version",argv[1])==0){
          version_of_the_tool();
          }
    else if(strcmp("-i",argv[1]) == 0||strcmp("-interface",argv[1]) ==0 ){
          if(argc<3){
                  printf("ERROR : please  provide an interface to sniff on it .. \n");
                  printf("------------------------------------------------------\n");
                  details_about_interface();
                  printf("\n Usage %s -i <interface> [you can look for the interface using -l or --lookup]\n",argv[0]);
                  }else{
                      sniff_start(argv[2]);
                    }
          
          }
          else{
            printf("\t\t\t Invalid argument 📌️ \n");
            help_to_user(argv[0]);
            }
    return 0;     
}
