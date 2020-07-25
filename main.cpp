#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
//#include <rte_ip.h>

struct ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};

struct ip *ipv4_hdr;
struct tcphdr *tcp_hdr;

int main(int argc, char *argv[]){
	if(argc < 2){
		printf("usage %s <network-interface>\n",argv[0]);
		return 0;
	}
	
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "no found network interfaces %s: %s\n",dev, errbuf);
		return 0;
	}

	while(true){
		struct pcap_pkthdr* header;
		struct ethernet_hdr *eth_hdr;
		struct ip *ipv4_hdr;
		struct tcphdr *tcp_hdr;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0){
			continue;
		}else if(res == -1 || res == -2){
			printf("pcap packet %s",pcap_geterr(handle));
			exit(-1);
		}

		printf("%u bytes captured\n", header->caplen);
		printf("\n--ethernet Header--\n");

		eth_hdr = (struct ethernet_hdr *) packet;
		for(int i=0; i<ETHER_ADDR_LEN; i++){
			printf("%02x:", eth_hdr->ether_dhost[i]);
		}
		printf("\n");
		for(int j=0; j<ETHER_ADDR_LEN; j++){
			printf("%02x:", eth_hdr->ether_shost[j]);
		}

		printf("\n--Ipv4 Header--\n");
		ipv4_hdr = (struct ip *) (packet + sizeof(struct ethernet_hdr));
		//for(int k=0; k<4; k++){
		printf("src : %s\n", inet_ntoa(ipv4_hdr->ip_src));
		//}
		//for(int z=0; z<4; z++){
		printf("dst : %s\n", inet_ntoa(ipv4_hdr->ip_dst));
		//}

		printf("\n--tcp header--\n");
		tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ethernet_hdr) + sizeof(struct ip));
		printf("src port : %d\n", ntohs(tcp_hdr->source));
		printf("dst port : %d\n", ntohs(tcp_hdr->dest));

		printf("\n--packet header--\n");
		printf("ha..");

	pcap_close(handle);

	}


	return 0;

}
