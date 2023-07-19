#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

char* s_getIpAddress(const char* ifr) {
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in* sin;
    static char ip_addr[INET_ADDRSTRLEN];
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, ifr);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        perror("ioctl() SIOCGIFADDR error");
        return NULL;
    }
    sin = (struct sockaddr_in*)&ifrq.ifr_addr;
    const char* ip = inet_ntoa(sin->sin_addr);
    strcpy(ip_addr, ip);

    close(sockfd);

    return ip_addr;
}

int main(int argc, char* args[]) {
    char* addr = s_getIpAddress("eth0");
    if (addr != NULL) {
        printf("ip addr: %s\n", addr);
    }

    return 0;
}

