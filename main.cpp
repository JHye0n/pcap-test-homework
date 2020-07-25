#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <stdint.h>
#include <netinet/in.h>

struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct ipv4_hdr
{
	struct in_addr ip_src, ip_dst;
};


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
		struct ipv4_hdr *ipv4_hdr;
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
		//packet += sizeof(struct ethernet_hdr);
		ipv4_hdr = (struct ipv4_hdr *) packet;
		printf("src : %s\n", inet_ntoa(ipv4_hdr->ip_src));
		printf("dst : %s\n", inet_ntoa(ipv4_hdr->ip_dst));
		//printf("sibal....");
		
		printf("\n--tcp header--\n");
		printf("test\n");


	}


	return 0;
}
