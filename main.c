#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage(){
	printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


char* get_mac_address(void) {
    int socket_fd;
    int count_if;

    struct ifreq *t_if_req;
    struct ifconf t_if_conf;

    char* arr_mac_addr = (char*) malloc(18 * sizeof(char));
    memset(arr_mac_addr, 0, 18);

    memset(&t_if_conf, 0, sizeof(t_if_conf));

    t_if_conf.ifc_ifcu.ifcu_req = NULL;
    t_if_conf.ifc_len = 0;

    if ((socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return NULL;
    }

    if (ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0) {
        close(socket_fd);
        free(arr_mac_addr);
        return NULL;
    }

    if ((t_if_req = (struct ifreq*) malloc(t_if_conf.ifc_len)) == NULL) {
        close(socket_fd);
        free(t_if_req);
        free(arr_mac_addr);
        return NULL;

    } else {
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req;
        if (ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0) {
            close(socket_fd);
            free(t_if_req);
            free(arr_mac_addr);
            return NULL;
        }

        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for (int idx = 0; idx < count_if; idx++) {
            struct ifreq* req = &t_if_req[idx];

            if (!strcmp(req->ifr_name, "lo")) {
                continue;
            }

            if (ioctl(socket_fd, SIOCGIFHWADDR, req) < 0) {
                break;
            }

            snprintf(arr_mac_addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                     (unsigned char) req->ifr_hwaddr.sa_data[0],
                     (unsigned char) req->ifr_hwaddr.sa_data[1],
                     (unsigned char) req->ifr_hwaddr.sa_data[2],
                     (unsigned char) req->ifr_hwaddr.sa_data[3],
                     (unsigned char) req->ifr_hwaddr.sa_data[4],
                     (unsigned char) req->ifr_hwaddr.sa_data[5]);
            break;
        }
    }

    close(socket_fd);
    free(t_if_req);

    return arr_mac_addr;
}

int main(int argc, char* argv[]) {
	if (argc != 4){
		usage();
		return -1;
	}
	char* dev = argv[1];
    	char* mac_address = get_mac_address();
    	if (mac_address != NULL) {
        	printf("MAC address: [%s]\n", mac_address);
        	free(mac_address);
    	} else {
        	printf("Failed to retrieve MAC address.\n");
    	}


    	return 0;
}

