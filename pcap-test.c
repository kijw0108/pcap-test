#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

typedef struct ether_header ether_hdr;
typedef struct ip ip_hdr;
typedef struct tcphdr tcp_hdr;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
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
		//get Ethernet
		ether_hdr *Ether = (ether_hdr *)packet;

		//get IP
		ip_hdr *Ip = (ip_hdr *)(packet + sizeof(ether_hdr));

		//get TCP
		tcp_hdr *Tcp = (tcp_hdr*)(packet + sizeof(ether_hdr) + Ip->ip_hl * 4);

		if(ntohs(Ether->ether_type) == ETHERTYPE_IP && Ip->ip_p == IPPROTO_TCP) {
			printf("=====================================\n");
			printf("-Ethernet Header-\n");
			printf("Source Mac : %s\n", ether_ntoa((ether_hdr *)Ether->ether_shost));
			printf("Destination Mac : %s\n", ether_ntoa((ether_hdr *)Ether->ether_dhost));

			printf("-IP Header-\n");
			printf("Source IP : %s\n", inet_ntoa(Ip->ip_src));
			printf("Destination IP : %s\n", inet_ntoa(Ip->ip_dst));

			printf("-TCP Header-\n");
			printf("Source Port : %d\n", ntohs(Tcp->th_sport));
			printf("Destination Port : %d\n", ntohs(Tcp->th_dport));

			int hdrsize = sizeof(ether_hdr) + Ip->ip_hl * 4 + Tcp->th_off * 4;
			int datasize = header->caplen - hdrsize;
			datasize = datasize < 8 ? datasize : 8;
			char *data = (char *)(packet + hdrsize);

			printf("-Data-\n");
			for(int i = 0; i < datasize; i++) {
				printf("%x", data[i]);
			}
			printf("\n");
		}
	}

	pcap_close(pcap);
}
