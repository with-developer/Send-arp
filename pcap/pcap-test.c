#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETHER_TYPE_ARP 0x0806

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};


struct libnet_arp_hdr
{
    u_int16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    u_int16_t ar_pro;         /* format of protocol address */
    u_int8_t  ar_hln;         /* length of hardware address */
    u_int8_t  ar_pln;         /* length of protocol addres */
    u_int16_t ar_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
    u_int8_t sender_mac[ETHER_ADDR_LEN];
    u_int8_t sender_ip[IP_ADDR_LEN];
    u_int8_t target_mac[ETHER_ADDR_LEN];
    u_int8_t target_ip[IP_ADDR_LEN];
};

void printMAC(u_int8_t* src_mac, u_int8_t* dst_mac){
        printf("Source Mac: %02x %02x %02x %02x %02x %02x\n", src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
        printf("Destination Mac: %02x %02x %02x %02x %02x %02x\n", dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
}

void printIP(u_int8_t* sender_ip, u_int8_t* target_ip) {
    printf("Sender IP: %d.%d.%d.%d\n",sender_ip[0],sender_ip[1],sender_ip[2],sender_ip[3]);
    printf("Target IP: %d.%d.%d.%d\n",target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
}


void usage() {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
}

typedef struct {
        char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
        if (argc != 2) {
                usage();
                return false;
        }
        param->dev_ = argv[1];
        return true;
}

int main(int argc, char* argv[]) {
        if (!parse(&param, argc, argv))
                return -1;

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
                return -1;
        }

        while (true) {
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(pcap, &header, &packet);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                        break;
                }


                struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + sizeof(*eth_hdr));

		printf("\n%u bytes captured\n", header->caplen);	
                
                
		if(ntohs(eth_hdr -> ether_type) != ETHER_TYPE_ARP) {
			printf("This packet is not ARP\n");
			continue;
		}
		printMAC(eth_hdr -> ether_shost, eth_hdr -> ether_dhost);
               
	       	printMAC(arp_hdr -> sender_mac, arp_hdr -> target_mac);	
		printIP(arp_hdr -> sender_ip, arp_hdr -> target_ip);
                
        }

        pcap_close(pcap);
}
