#ifndef __PACKET_H__
#define __PACKET_H__
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void eth_header(const u_char * , int );
void ip_header(const u_char * , int );
void tcp_packet(const u_char * , int );
void data(const u_char * , int );
#endif
