#include "ping.h"

struct sockaddr_in dest_addr;
int sockfd, datalen = PACKET_SIZE;
pid_t pid;
int nsend = 0, nreceived = 0;
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
struct timeval tvrecv;
int quiet_mode = 0;
int verbose_mode = 0;  // New variable for verbose mode
int count = MAX_NO_PACKETS;  // New variable for count
int interval = 1;  // New variable for interval
int packet_size = PACKET_SIZE;  // New variable for packet size
int broadcast = 0; // Variable for broadcast mode

void print_help() {
    printf("Usage: ping [options] <destination>\n");
    printf("Options:\n");
    printf("  -h           Display help information\n");
    printf("  -b           Allow pinging a broadcast address (IPv4 only)\n");
    printf("  -t <ttl>     Set the TTL value (IPv4 only)\n");
    printf("  -q           Quiet mode, only display summary at the end\n");
    printf("  -D           Print timestamps\n");
    printf("  -c <count>   Stop after <count> replies\n");
    printf("  -i <interval> Seconds between sending each packet\n");
    printf("  -s <size>    Use <size> as number of data bytes to be sent\n");
    printf("  -v           Verbose output\n");
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

void enable_verbose_mode() {
    verbose_mode = 1;
}

void set_count(int c) {
    count = c;
}

void set_interval(int i) {
    interval = i;
}

void set_packet_size(int size) {
    packet_size = size;
    datalen = size;
}

void print_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("[%ld.%06ld] ", tv.tv_sec, tv.tv_usec);
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
    icmp->icmp_cksum = checksum((unsigned char *)icmp, packetsize);

    if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto error");
    }

    if (verbose_mode) {
        printf("Sent ICMP packet to %s, seq=%d\n", inet_ntoa(dest_addr.sin_addr), icmp->icmp_seq);
    }
}

void recv_packet() {
    int n;
    struct ip *ip;
    struct icmp *icmp;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, &fromlen)) < 0) {
        if (errno == EINTR) {
            return;
        }
        perror("recvfrom error");
        return;
    }

    gettimeofday(&tvrecv, NULL);
    ip = (struct ip *)recvpacket;
    icmp = (struct icmp *)(recvpacket + (ip->ip_hl << 2));
    if (icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == pid) {
        if (verbose_mode) {
            printf("Received ICMP packet from %s, seq=%d\n", inet_ntoa(from.sin_addr), icmp->icmp_seq);
        }
        nreceived++;
        if (!quiet_mode) {
            print_timestamp();
            tv_sub(&tvrecv, (struct timeval *)icmp->icmp_data);
            double rtt = tvrecv.tv_sec * 1000.0 + tvrecv.tv_usec / 1000.0;
            printf("%d bytes from %s: icmp_seq=%u ttl=%d time=%.3f ms\n",
                   n - (ip->ip_hl << 2), inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
        }
    }
}

void statistics() {
    printf("\n--- ping statistics ---\n");
    printf("%d packets transmitted, %d received, %.0f%% packet loss\n",
           nsend, nreceived, ((nsend - nreceived) / (double)nsend) * 100.0);
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
    char *destination;
    int ch, ttl = 64;
    int print_timestamps = 0;

    while ((ch = getopt(argc, argv, "hbt:qDc:i:s:v")) != -1) {
        switch (ch) {
            case 'h':
                print_help();
                exit(0);
            case 'b':
                broadcast = 1;
                break;
            case 't':
                ttl = atoi(optarg);
                break;
            case 'q':
                enable_quiet_mode();
                break;
            case 'D':
                print_timestamps = 1;
                break;
            case 'c':
                set_count(atoi(optarg));
                break;
            case 'i':
                set_interval(atoi(optarg));
                break;
            case 's':
                set_packet_size(atoi(optarg));
                break;
            case 'v':
                enable_verbose_mode();
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

    alarm(MAX_WAIT_TIME);  // Set timeout
    for (int i = 0; i < count; i++) {
        send_packet();
        recv_packet();
        sleep(interval);
    }

    statistics();

    return 0;
}
