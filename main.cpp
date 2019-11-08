#define WIN32

#include<iostream>
#include"pcap.h"
#include<winsock2.h>
#include "main.h"
#include"Packet.h"
#include"HTTPParse.h"

#pragma comment(lib,"wpcap.lib")   
#pragma comment(lib,"packet.lib")   
#pragma comment(lib,"ws2_32.lib")   

#pragma warning( disable : 4996 )

using namespace std;

int i = 0;
string input = "";

void printmac(u_char* c) {
	for (int i = 0; i < 6; ++i) {
		if (i == 0)
			printf("%02X", c[i]);
		else
			printf("-%02X", c[i]);
	}
	//printf("\n");
}
void printeheader(Ethernet_Header * eheader) {
		printf("Ŀ�ĵ�ַ��");
		printmac(eheader->dstaddr.bytes);
		printf(" | Դ��ַ��");
		printmac(eheader->srcaddr.bytes);
		printf(" | ���ͣ�");
		printf("%04X", ntohs(eheader->eth_type));
		printf("\n");
}

void printipheader(IP_Header * ipheader) {
	//u_char		ver_headerlen;			// �汾��(4 bits) + �ײ�����(4 bits)
	//u_char		tos;					// ��������
	//u_short		totallen;				// �ܳ���
	//u_short		identifier;				// ��ʶ
	//u_short		flags_offset;			// ��־(3 bits) + Ƭƫ��(13 bits)
	//u_char		ttl;					// ����ʱ��
	//u_char		protocol;				// �ϲ�Э��
	//u_short		checksum;				// �ײ�У���
	//IP_Address	srcaddr;				// Դ��ַ
	//IP_Address	dstaddr;				// Ŀ�ĵ�ַ
	//u_int		option_padding;			// ѡ������
	u_int ip_version = ipheader->ver_headerlen >> 4;
	u_int ip_len = (ipheader->ver_headerlen & 0xf) * 4; // 0xf ȡ����λ
	int tlen = ntohs(ipheader->totallen);
	u_short flags_of = ntohs(ipheader->flags_offset);
	u_short of = (flags_of & 0x07ff);
	u_char flags = flags_of >> 13;


	printf("IP���� ��%d.%d.%d.%d --> %d.%d.%d.%d \nDataLen��%d\n", ipheader->dstaddr.bytes[0],
		ipheader->dstaddr.bytes[1],
		ipheader->dstaddr.bytes[2],
		ipheader->dstaddr.bytes[3],
		ipheader->dstaddr.bytes[0],
		ipheader->dstaddr.bytes[1],
		ipheader->dstaddr.bytes[2],
		ipheader->dstaddr.bytes[3],
		tlen - ip_len);
	printf("-----------------------------------------------------\n");
	printf("|IPv%d   |�ײ����� %4d|�������� %4d|�ܳ��� %8d|\n", ip_version, ip_len, ipheader->tos, tlen);
	printf("-----------------------------------------------------\n");
	printf("|��ʶ %12d|��־ %6d|Ƭƫ�� %14d|\n", ipheader->identifier, flags, ntohs(of));
	printf("-----------------------------------------------------\n");
	printf("|����ʱ�� %8d|�ϲ�Э�� %4d|�ײ�У��� %8d|\n", ipheader->ttl, ipheader->protocol, ntohs(ipheader->checksum));
	printf("-----------------------------------------------------\n");
	printf("|Դ��ַ   %3d.%3d.%3d.%3d                           |\n",
		ipheader->srcaddr.bytes[0],
		ipheader->srcaddr.bytes[1],
		ipheader->srcaddr.bytes[2],
		ipheader->srcaddr.bytes[3]);
	printf("-----------------------------------------------------\n");
	printf("|Ŀ�ĵ�ַ %3d.%3d.%3d.%3d                           |\n",
		ipheader->dstaddr.bytes[0],
		ipheader->dstaddr.bytes[1],
		ipheader->dstaddr.bytes[2],
		ipheader->dstaddr.bytes[3]);
	//printf("data len : %d\n", tlen - ip_len);
	printf("-----------------------------------------------------\n");
}

int* ten2two(int ten) {
	static int ans[50];
	int j = 0;
	while (ten) {
		ans[j] = ten % 2;
		ten /= 2;
		j++;
	}

	return ans;
}

void printtcpheader(TCP_Header * tcpheader) {
	u_short sport = ntohs(tcpheader->srcport);
	u_short dport = ntohs(tcpheader->dstport);
	int seq = ntohs(tcpheader->seq);
	int ack_seq = ntohs(tcpheader->ack);
	u_short tcph_len = tcpheader->headerlen_rsv_flags >> 12;
	u_short rsv = (tcpheader->headerlen_rsv_flags & 0xfc0) >> 6;
	u_short flags = tcpheader->headerlen_rsv_flags & 0x3f;
	u_short urg = flags >> 5;
	u_short ack = (flags & 0x1f) >> 4;
	u_short psh = (flags & 0xf) >> 3;
	u_short rst = (flags & 0x7) >> 2;
	u_short syn = (flags & 0x3) >> 1;
	u_short fin = (flags & 0x1);
	u_short winsize = tcpheader->win_size;
	u_short chksum = tcpheader->chksum;
	u_short urgptr = tcpheader->urg_ptr;
	int option = tcpheader->option;
	printf("TCP����\n");
	printf("----------------------------------------------------------------------------\n");
	printf("|Դ�˿ں�  %26d|Ŀ�Ķ˿ں� %26d|\n",sport,dport);
	printf("----------------------------------------------------------------------------\n");
	printf("|32λSeq %66d|\n", seq);
	printf("----------------------------------------------------------------------------\n");
	printf("|32λAck %66d|\n", ack_seq);
	printf("----------------------------------------------------------------------------\n");
	//int rsv_a[6] = ten2two(rsv);
	
	printf("|�ײ����� %2d|����λ %4d|URG %d|ACK %d|PSH %d|RST %d|SYN %d|FIN %d|���ڴ�С %5d|\n", tcph_len * 4, rsv,
		urg,ack,psh,rst,syn,fin, winsize);
	printf("----------------------------------------------------------------------------\n");
	printf("|�����  %28d|����ָ�� %28d|\n", chksum, chksum);
	printf("----------------------------------------------------------------------------\n");
}

void printudpheader(UDP_Header * udpheader) {
	//u_short		srcport;				// Դ�˿�
	//u_short		dstport;				// Ŀ�Ķ˿�
	//u_short		len;					// ����
	//u_short		checksum;				// У���

	u_short sport = ntohs(udpheader->srcport);
	u_short dport = ntohs(udpheader->dstport);
	u_short len = ntohs(udpheader->len);
	u_short checksum = ntohs(udpheader->checksum);
	printf("UDP����\n");
	printf("------------------------------------\n");
	printf("|Դ�˿�  %8d|Ŀ�Ķ˿� %8d|\n", sport, dport);
	printf("------------------------------------\n");
	printf("|����    %8d|У���   %8d|\n", len, checksum);
	printf("------------------------------------\n");
	printf("%s\n", (char*)udpheader + 8);

}

void printarpheader(ARP_Header * arpheader) {
	//u_short		hwtype;					// Ӳ������
	//u_short		ptype;					// Э������
	//u_char		hwlen;					// Ӳ������
	//u_char		plen;					// Э�鳤��
	//u_short		opcode;					// ������
	//MAC_Address	srcmac;					// ԴMAC��ַ
	//IP_Address	srcip;					// ԴIP��ַ
	//MAC_Address	dstmac;					// Ŀ��MAC��ַ
	//IP_Address	dstip;					// Ŀ��IP��ַ

	printf("ARP����\n");
	printf("--------------------------------------------------------------\n");
	printf("|  ԴMAC��ַ |");
	printmac(arpheader->srcmac.bytes);
	printf("|  ԴIP��ַ   %3d.%3d.%3d.%3d |\n",
		arpheader->srcip.bytes[0],
		arpheader->srcip.bytes[1],
		arpheader->srcip.bytes[2],
		arpheader->srcip.bytes[3]);
	printf("--------------------------------------------------------------\n");
	printf("|Ŀ��MAC��ַ |");
	printmac(arpheader->dstmac.bytes);
	printf("|Ŀ��IP��ַ   %3d.%3d.%3d.%3d |\n",
		arpheader->dstip.bytes[0],
		arpheader->dstip.bytes[1],
		arpheader->dstip.bytes[2],
		arpheader->dstip.bytes[3]);
	printf("--------------------------------------------------------------\n");
}

void printicmpheader(ICMP_Header *icmpheader) {
	//u_char		type;					// ����
	//u_char		code;					// ����
	//u_short		chksum;					// У���
	//u_int		others;					// �ײ��������֣��ɱ���������ȷ����Ӧ���ݣ�

	printf("ICMP����\n");
	printf("------------------------------------\n");
	printf("|���� %4d|���� %4d|У��� %8d|\n", icmpheader->type, icmpheader->code, ntohs(icmpheader->chksum));
	printf("------------------------------------\n");
	//printf("|��ʶ�� %8d|���к� %8d|\n", icmpheader->);
}


/* �ص�����ԭ�� */
/* �ص����������յ�ÿһ�����ݰ�ʱ�ᱻlibpcap������ */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* ��ӡ���ݰ���ʱ����ͳ��� */
	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);


	//һ���������ݰ�
	Packet pkt(header, pkt_data, i++);
	//���ݲ������ˣ���ӡ��ʾ
	input = "HTTP";
	if (pkt.decodeEthernet() == 0) {
		Ethernet_Header * eheader = pkt.ethh;
		IP_Header * ipheader = pkt.iph;
		TCP_Header * tcpheader = pkt.tcph;
		UDP_Header * udpheader = pkt.udph;
		ARP_Header * arpheader = pkt.arph;
		ICMP_Header *icmpheader = pkt.icmph;

		if (input == "E") {
			printeheader(eheader);
		}
		else if (ipheader != nullptr & input == "IP") {
			printipheader(ipheader);
		}
		else if (tcpheader != nullptr & input == "TCP") {
			printtcpheader(tcpheader);
		}
		else if (udpheader != nullptr & input == "UDP") {
			printudpheader(udpheader);
		}
		else if (arpheader != nullptr & input == "ARP") {
			printarpheader(arpheader);
		}
		else if (icmpheader != nullptr & input == "ICMP") {
			printicmpheader(icmpheader);
		}
		else if (input == "HTTP" & pkt.protocol == "HTTP") {
			//HTTPParse httpParse;
			//httpParse.parse((char*)pkt.httpmsg, pkt.getL4PayloadLength());
			printf("HTTP���ݱ�-------------------------------------------------------------------------\n");
			//printf("--------------------------------------------------------------------------------\n");
			//for (auto i = httpParse.kvs.begin(); i != httpParse.kvs.end(); i++) {
			//	printf("|%20s | %.30s|\n", i->first.c_str(), i->second.c_str());
			//	printf("--------------------------------------------------------------------------------\n");

			//}

			printf("%s\n", (char*)pkt.httpmsg);
		}
		/*else if (pkt.protocol == "ICMP") {
			printf("%s\n", pkt.protocol.c_str());
			printf("%d\n", pkt.icmph->code);
		}*/
	}
}


int main(int argc, char *argv[])
{
	if (argc > 1) {
		input = string(argv[1], argv[1] + strlen(argv[1]));
	}
	//printf("%d\n", argc);
	//printf("%s\n", input.c_str());
	//return 0;
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "";
	struct bpf_program fcode;

	/* ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת����ѡ�豸 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* �������� */
	if ((adhandle = pcap_open(d->name,  // �豸��
		65536,     // Ҫ��׽�����ݰ��Ĳ��� 
				   // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,         // ����ģʽ
		1000,      // ��ȡ��ʱʱ��
		NULL,      // Զ�̻�����֤
		errbuf     // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ���������·�㣬Ϊ�˼򵥣�����ֻ������̫�� */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;


	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	/* ��ʼ��׽ */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

