/* push test */
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
    uint16_t  ether_type;              /* protocol */
};

struct ip *ipv4_hdr;
struct tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
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
		printf("no found network interfaces %s: %s\n",dev, errbuf);
		return 0;
	}

	while(true){
		struct pcap_pkthdr* header;
		struct ethernet_hdr *eth_hdr;
		struct ip *ipv4_hdr;
		struct tcp_hdr *tcp_addr;
		const u_char *packet;
		const u_char *payload;
		//unsigned int ethet_type;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0){
			continue;
		}else if(res == -1 || res == -2){
			printf("pcap packet %s",pcap_geterr(handle));
			exit(-1);
		}

		printf("\n%u bytes captured\n", header->caplen);

		eth_hdr = (struct ethernet_hdr *) packet;

		//gilgil codeview update(0727)

		if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
			return -1;
		}
	
		printf("\n--ethernet header--\n");
		for(int i=0; i<ETHER_ADDR_LEN; i++){
			printf("%02x:", eth_hdr->ether_dhost[i]);
		}
		printf("\n");
		for(int j=0; j<ETHER_ADDR_LEN; j++){
			printf("%02x:", eth_hdr->ether_shost[j]);
		}
	
		printf("\n--Ipv4 Header--\n");
		ipv4_hdr = (struct ip *) (packet + sizeof(struct ethernet_hdr));
		//example

		//char* s_ip = inet_ntoa(ipv4_hdr->ip_src);
		//char* d_ip = inet_ntoa(ipv4_hdr->ip_dst);
		//printf("src : %s\n", s_ip);
		//printf("dst : %s\n", d_ip);

		printf("src : %s\n", inet_ntoa(ipv4_hdr->ip_src));
		printf("dst : %s\n", inet_ntoa(ipv4_hdr->ip_dst));

		printf("\n--tcp header--\n");
		tcp_addr = (struct tcp_hdr *)(packet + sizeof(struct ethernet_hdr) + sizeof(struct ip));
		printf("src port : %d\n", ntohs(tcp_addr->th_sport));
		printf("dst port : %d\n", ntohs(tcp_addr->th_dport));

		printf("\n--payload(data)--\n");
		payload = (u_char *)(packet + sizeof(ethernet_hdr) + sizeof(struct ip) + sizeof(tcp_hdr));
		payload += 16;
		

            	for(int a=0; a<16; a++){
			printf("|%02x|", payload[a]);
		}
		printf("\n--end--\n");

	}


	return 0;

}
