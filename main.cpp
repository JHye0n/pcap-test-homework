#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include <stdint.h>

struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

int main(int argc, char *argv[]){
	if(argc != 2){
		printf("usage %s <network-interface>\n",argv[0]);
		return 0;
	}
	
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *pkthdr;
	struct ethernet_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	const u_char *pkdata;
	int i=0,j=0;
	uint8_t k=0;
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "no found network interfaces %s: %s\n",dev, errbuf);
		return 0;
	}

	while(1){
		int res = pcap_next_ex(handle, &pkthdr, &pkdata);
		if(res == 0){
			continue;
		}else if(res == -1 || res == -2){
			fprintf(stderr, "pcap packet %s",pcap_geterr(handle));
			exit(-1);
		}

		printf("%u bytes captured\n", pkthdr->caplen);
	
		for(i=0; i<ETHER_ADDR_LEN; i++){
			printf("%02x:", eth_hdr->ether_dhost[i]);
		}
		printf("-->");
		for(j=0; j<ETHER_ADDR_LEN; j++){
			printf("%02x:", eth_hdr->ether_shost[j]);
		}
		printf("\n");
		
	}


	return 0;
}
