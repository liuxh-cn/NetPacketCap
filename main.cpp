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
		printf("目的地址：");
		printmac(eheader->dstaddr.bytes);
		printf(" | 源地址：");
		printmac(eheader->srcaddr.bytes);
		printf(" | 类型：");
		printf("%04X", ntohs(eheader->eth_type));
		printf("\n");
}

void printipheader(IP_Header * ipheader) {
	//u_char		ver_headerlen;			// 版本号(4 bits) + 首部长度(4 bits)
	//u_char		tos;					// 服务类型
	//u_short		totallen;				// 总长度
	//u_short		identifier;				// 标识
	//u_short		flags_offset;			// 标志(3 bits) + 片偏移(13 bits)
	//u_char		ttl;					// 生存时间
	//u_char		protocol;				// 上层协议
	//u_short		checksum;				// 首部校验和
	//IP_Address	srcaddr;				// 源地址
	//IP_Address	dstaddr;				// 目的地址
	//u_int		option_padding;			// 选项和填充
	u_int ip_version = ipheader->ver_headerlen >> 4;
	u_int ip_len = (ipheader->ver_headerlen & 0xf) * 4; // 0xf 取后四位
	int tlen = ntohs(ipheader->totallen);
	u_short flags_of = ntohs(ipheader->flags_offset);
	u_short of = (flags_of & 0x07ff);
	u_char flags = flags_of >> 13;


	printf("IP报文 ：%d.%d.%d.%d --> %d.%d.%d.%d \nDataLen：%d\n", ipheader->dstaddr.bytes[0],
		ipheader->dstaddr.bytes[1],
		ipheader->dstaddr.bytes[2],
		ipheader->dstaddr.bytes[3],
		ipheader->dstaddr.bytes[0],
		ipheader->dstaddr.bytes[1],
		ipheader->dstaddr.bytes[2],
		ipheader->dstaddr.bytes[3],
		tlen - ip_len);
	printf("-----------------------------------------------------\n");
	printf("|IPv%d   |首部长度 %4d|服务类型 %4d|总长度 %8d|\n", ip_version, ip_len, ipheader->tos, tlen);
	printf("-----------------------------------------------------\n");
	printf("|标识 %12d|标志 %6d|片偏移 %14d|\n", ipheader->identifier, flags, ntohs(of));
	printf("-----------------------------------------------------\n");
	printf("|生存时间 %8d|上层协议 %4d|首部校验和 %8d|\n", ipheader->ttl, ipheader->protocol, ntohs(ipheader->checksum));
	printf("-----------------------------------------------------\n");
	printf("|源地址   %3d.%3d.%3d.%3d                           |\n",
		ipheader->srcaddr.bytes[0],
		ipheader->srcaddr.bytes[1],
		ipheader->srcaddr.bytes[2],
		ipheader->srcaddr.bytes[3]);
	printf("-----------------------------------------------------\n");
	printf("|目的地址 %3d.%3d.%3d.%3d                           |\n",
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
	printf("TCP报文\n");
	printf("----------------------------------------------------------------------------\n");
	printf("|源端口号  %26d|目的端口号 %26d|\n",sport,dport);
	printf("----------------------------------------------------------------------------\n");
	printf("|32位Seq %66d|\n", seq);
	printf("----------------------------------------------------------------------------\n");
	printf("|32位Ack %66d|\n", ack_seq);
	printf("----------------------------------------------------------------------------\n");
	//int rsv_a[6] = ten2two(rsv);
	
	printf("|首部长度 %2d|保留位 %4d|URG %d|ACK %d|PSH %d|RST %d|SYN %d|FIN %d|窗口大小 %5d|\n", tcph_len * 4, rsv,
		urg,ack,psh,rst,syn,fin, winsize);
	printf("----------------------------------------------------------------------------\n");
	printf("|检验和  %28d|紧急指针 %28d|\n", chksum, chksum);
	printf("----------------------------------------------------------------------------\n");
}

void printudpheader(UDP_Header * udpheader) {
	//u_short		srcport;				// 源端口
	//u_short		dstport;				// 目的端口
	//u_short		len;					// 长度
	//u_short		checksum;				// 校验和

	u_short sport = ntohs(udpheader->srcport);
	u_short dport = ntohs(udpheader->dstport);
	u_short len = ntohs(udpheader->len);
	u_short checksum = ntohs(udpheader->checksum);
	printf("UDP报文\n");
	printf("------------------------------------\n");
	printf("|源端口  %8d|目的端口 %8d|\n", sport, dport);
	printf("------------------------------------\n");
	printf("|长度    %8d|校验和   %8d|\n", len, checksum);
	printf("------------------------------------\n");
	printf("%s\n", (char*)udpheader + 8);

}

void printarpheader(ARP_Header * arpheader) {
	//u_short		hwtype;					// 硬件类型
	//u_short		ptype;					// 协议类型
	//u_char		hwlen;					// 硬件长度
	//u_char		plen;					// 协议长度
	//u_short		opcode;					// 操作码
	//MAC_Address	srcmac;					// 源MAC地址
	//IP_Address	srcip;					// 源IP地址
	//MAC_Address	dstmac;					// 目的MAC地址
	//IP_Address	dstip;					// 目的IP地址

	printf("ARP报文\n");
	printf("--------------------------------------------------------------\n");
	printf("|  源MAC地址 |");
	printmac(arpheader->srcmac.bytes);
	printf("|  源IP地址   %3d.%3d.%3d.%3d |\n",
		arpheader->srcip.bytes[0],
		arpheader->srcip.bytes[1],
		arpheader->srcip.bytes[2],
		arpheader->srcip.bytes[3]);
	printf("--------------------------------------------------------------\n");
	printf("|目的MAC地址 |");
	printmac(arpheader->dstmac.bytes);
	printf("|目的IP地址   %3d.%3d.%3d.%3d |\n",
		arpheader->dstip.bytes[0],
		arpheader->dstip.bytes[1],
		arpheader->dstip.bytes[2],
		arpheader->dstip.bytes[3]);
	printf("--------------------------------------------------------------\n");
}

void printicmpheader(ICMP_Header *icmpheader) {
	//u_char		type;					// 类型
	//u_char		code;					// 代码
	//u_short		chksum;					// 校验和
	//u_int		others;					// 首部其他部分（由报文类型来确定相应内容）

	printf("ICMP报文\n");
	printf("------------------------------------\n");
	printf("|类型 %4d|代码 %4d|校验和 %8d|\n", icmpheader->type, icmpheader->code, ntohs(icmpheader->chksum));
	printf("------------------------------------\n");
	//printf("|标识符 %8d|序列号 %8d|\n", icmpheader->);
}


/* 回调函数原型 */
/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* 打印数据包的时间戳和长度 */
	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);


	//一层层解析数据包
	Packet pkt(header, pkt_data, i++);
	//根据参数过滤，打印显示
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
			printf("HTTP数据报-------------------------------------------------------------------------\n");
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

	/* 获得设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
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
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* 打开适配器 */
	if ((adhandle = pcap_open(d->name,  // 设备名
		65536,     // 要捕捉的数据包的部分 
				   // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
		1000,      // 读取超时时间
		NULL,      // 远程机器验证
		errbuf     // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 开始捕捉 */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

