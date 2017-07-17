#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "packet.h"

int main()
{    
    pcap_t *handle;
 
    char errbuf[100];  
     
    handle = pcap_open_live("eth0" , 65536 , 1 , 0 , errbuf);  //pcaket open

    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , "eth0" , errbuf);
        exit(1);
    }
    
    pcap_loop(handle , -1 , process_packet , NULL);
     
    return 0;   
}
