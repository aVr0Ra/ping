#include "ping.h"

struct sockaddr_in dest_addr;
int sockfd, datalen = PACKET_SIZE;
pid_t pid;
int nsend = 0, nreceived = 0;
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
struct timeval tvrecv;
int quiet_mode = 0;
int broadcast = 0;

void print_help() {
    printf("Usage: ping [options] <destination>\n");
    printf("Options:\n");
    printf("  -h           Display help information\n");
    printf("  -b           Allow pinging a broadcast address (IPv4 only)\n");
    printf("  -t <ttl>     Set the TTL value (IPv4 only)\n");
    printf("  -q           Quiet mode, only display summary at the end\n");
}

void set_ttl(int sockfd, int ttl) {
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("Setting TTL failed");
        exit(EXIT_FAILURE);
    }
}

void enable_broadcast(int sockfd) {
    int broadcast = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        perror("Setting broadcast option failed");
        exit(EXIT_FAILURE);
    }
}

void enable_quiet_mode() {
    quiet_mode = 1;
}

unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void tv_sub(struct timeval *out, struct timeval *in) {
    if ((out->tv_usec -= in->tv_usec) < 0) {
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

void send_packet() {
    int packetsize;
    struct icmp *icmp;

    icmp = (struct icmp *)sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = nsend++;
    icmp->icmp_id = pid;
    gettimeofday((struct timeval *)icmp->icmp_data, NULL);
    packetsize = 8 + datalen;
    icmp->icmp_cksum = checksum((unsigned short *)icmp, packetsize);

    if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto error");
    } else if (!quiet_mode) {
        printf("Packet sent: %d bytes to %s\n", packetsize, inet_ntoa(dest_addr.sin_addr));
    }
}

void recv_packet() {
    int n, fromlen;
    struct sockaddr_in from;
    struct ip *ip;
    struct icmp *icmp;
    int iphdrlen;
    fromlen = sizeof(from);

    while ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen)) > 0) {
        gettimeofday(&tvrecv, NULL);
        ip = (struct ip *)recvpacket;
        iphdrlen = ip->ip_hl << 2;
        icmp = (struct icmp *)(recvpacket + iphdrlen);
        if (icmp->icmp_id == pid) {
            tv_sub(&tvrecv, (struct timeval *)icmp->icmp_data);
            double rtt = tvrecv.tv_sec * 1000.0 + tvrecv.tv_usec / 1000.0;
            if (!quiet_mode) {
                printf("%d bytes from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n", n, inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
            }
            nreceived++;
            return;  // 只处理一次接收到的数据包
        }
    }

    if (n < 0) {
        if (errno == EINTR) {
            return;
        }
        perror("recvfrom error");
    }
}

void statistics() {
    printf("\n--- ping statistics ---\n");
    printf("%d packets transmitted, %d received, %.0f%% packet loss\n", nsend, nreceived, ((nsend - nreceived) * 100.0) / nsend);
}

void timeout(int signo) {
    statistics();
    exit(0);
}

void int_handler(int signo) {
    statistics();
    exit(0);
}

int main(int argc, char *argv[]) {
    struct hostent *host;
    struct protoent *protocol;
    int ttl = 64;  // 默认TTL值
    char *destination;
    int opt;

    if (argc < 2) {
        print_help();
        exit(EXIT_FAILURE);
    }

    while ((opt = getopt(argc, argv, "hbt:q")) != -1) {
        switch (opt) {
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            case 'b':
                broadcast = 1;
                break;
            case 't':
                ttl = atoi(optarg);
                break;
            case 'q':
                enable_quiet_mode();
                break;
            default:
                print_help();
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Expected destination after options\n");
        exit(EXIT_FAILURE);
    }

    destination = argv[optind];

    if ((protocol = getprotobyname("icmp")) == NULL) {
        perror("getprotobyname");
        exit(EXIT_FAILURE);
    }

    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    set_ttl(sockfd, ttl);

    if (broadcast) {
        enable_broadcast(sockfd);
    }

    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (broadcast) {
        dest_addr.sin_addr.s_addr = inet_addr(destination);
    } else {
        if ((host = gethostbyname(destination)) == NULL) {
            perror("gethostbyname error");
            exit(EXIT_FAILURE);
        }
        bcopy((char *)host->h_addr, (char *)&dest_addr.sin_addr, host->h_length);
    }

    pid = getpid();
    signal(SIGALRM, timeout);
    signal(SIGINT, int_handler);

    // 设置循环发送和接收数据包
    alarm(MAX_WAIT_TIME);  // 设置超时时间
    while (nsend < MAX_NO_PACKETS) {
        send_packet();
        recv_packet();
        sleep(1);
    }

    statistics();

    return 0;
}
