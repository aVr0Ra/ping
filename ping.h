#ifndef PING_H
#define PING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>

#define PACKET_SIZE 64
#define MAX_WAIT_TIME 5
#define MAX_NO_PACKETS 4

void print_help();
void set_ttl(int sockfd, int ttl);
void enable_broadcast(int sockfd);
void enable_quiet_mode();
unsigned short checksum(void *b, int len);
void tv_sub(struct timeval *out, struct timeval *in);
void send_packet();
void recv_packet();
void statistics();
void timeout(int signo);
void int_handler(int signo);
void print_timestamp();

extern int quiet_mode;
extern int verbose_mode;  // New variable for verbose mode
extern int count;         // New variable for count
extern int interval;      // New variable for interval
extern int packet_size;   // New variable for packet size

#endif
