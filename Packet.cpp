#include "Packet.h"
#include "pcap.h"

Packet::Packet()
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;

	pkt_data = NULL;
	num = -1;
	header = NULL;
}

Packet::Packet(const Packet &p)
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;

	if (!p.isEmpty())
	{
		u_int caplen = p.header->caplen;

		pkt_data = (u_char*)malloc(caplen);
		memcpy(pkt_data, p.pkt_data, caplen);

		header = (struct pcap_pkthdr *)malloc(sizeof(*(p.header)));
		memcpy(header, p.header, sizeof(*(p.header)));

		num = p.num;

		decodeEthernet();
	}
	else
	{
		pkt_data = NULL;
		header = NULL;
		num = -1;
	}
}

Packet::Packet(const struct pcap_pkthdr *header, const u_char *pkt_data, const u_short &packetNum)
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;
	num = packetNum;

	if (pkt_data != NULL && header != NULL)
	{
		this->pkt_data = (u_char*)malloc(header->caplen);
		memcpy(this->pkt_data, pkt_data, header->caplen);

		this->header = (struct pcap_pkthdr *)malloc(sizeof(*header));
		memcpy(this->header, header, sizeof(*header));

		decodeEthernet();
	}
	else
	{
		this->pkt_data = NULL;
		this->header = NULL;
	}
}

/**
*	@brief	��ֵ���������
*	@param	p	���ݰ�
*	@return ʵ������
*/
Packet & Packet::operator=(const Packet & p)
{
	if (this == &p)
	{
		return *this;
	}
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;


	if (!p.isEmpty())
	{
		u_int caplen = p.header->caplen;

		if (pkt_data == NULL)
		{
			pkt_data = (u_char*)malloc(caplen);
		}
		memcpy(pkt_data, p.pkt_data, caplen);

		if (header == NULL)
		{
			header = (struct pcap_pkthdr *)malloc(sizeof(*(p.header)));
		}
		memcpy(header, p.header, sizeof(*(p.header)));

		num = p.num;

		decodeEthernet();
	}
	else
	{
		pkt_data = NULL;
		header = NULL;
		httpmsg = NULL;
		num = -1;
	}
	return *this;
}

Packet::~Packet()
{
	ethh = NULL;
	iph = NULL;
	arph = NULL;
	icmph = NULL;
	udph = NULL;
	tcph = NULL;
	dnsh = NULL;
	dhcph = NULL;
	httpmsg = NULL;
	num = -1;

	free(pkt_data);
	pkt_data = NULL;

	free(header);
	header = NULL;
	protocol = "";
}

/**
*	@brief	�ж����ݰ��Ƿ�Ϊ��
*	@param	-
*	@return true pkt_data��headerΪ��	false pkt_data��header������
*/
bool Packet::isEmpty() const
{
	if (pkt_data == NULL || header == NULL)
	{
		return true;
	}
	return false;
}

/**
*	@brief	����Ethernet֡���ó�Ա����ethh���棬����eth_typeֵ������һ��������
*	@param	-
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeEthernet()
{
	if (isEmpty())
	{
		return -1;
	}

	protocol = "Ethernet";
	ethh = (Ethernet_Header*)pkt_data;

	switch (ntohs(ethh->eth_type))
	{
	case ETHERNET_TYPE_IP:
		decodeIP(pkt_data + ETHERNET_HEADER_LENGTH);
		break;
	case ETHERNET_TYPE_ARP:
		decodeARP(pkt_data + ETHERNET_HEADER_LENGTH);
		break;
	default:
		break;
	}
	return 0;
}

/**
*	@brief	����IP���ݰ��ײ����ó�Ա����iph���棬����protocolֵ������һ��������
*	@param	L2payload	ָ��IP���ݰ���ָ��
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeIP(u_char * L2payload)
{
	if (L2payload == NULL)
	{
		return -1;
	}

	protocol = "IPv4";
	iph = (IP_Header*)(L2payload);
	u_short IPHeaderLen = (iph->ver_headerlen & 0x0f) * 4;
	switch (iph->protocol)
	{
	case PROTOCOL_ICMP:
		decodeICMP(L2payload + IPHeaderLen);
		break;

	case PROTOCOL_TCP:
		decodeTCP(L2payload + IPHeaderLen);
		break;

	case PROTOCOL_UDP:
		decodeUDP(L2payload + IPHeaderLen);
		break;

	default:
		break;
	}
	return 0;
}

/**
*	@brief	����ARP�����ײ����ó�Ա����arph����
*	@param	L2payload	ָ��ARP���ĵ�ָ��
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeARP(u_char * L2payload)
{
	if (L2payload == NULL)
	{
		return -1;
	}
	protocol = "ARP";
	arph = (ARP_Header*)(L2payload);

	return 0;
}

/**
*	@brief	����ICMP�����ײ����ó�Ա����icmph����
*	@param	L2payload	ָ��ICMP���ĵ�ָ��
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeICMP(u_char * L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "ICMP";
	icmph = (ICMP_Header*)(L3payload);
	return 0;
}

/**
*	@brief	����TCP���Ķ��ײ����ó�Ա����tcph���棬����ԴĿ�˿�ѡ����һ��������
*	@param	L3payload	ָ��TCP���Ķε�ָ��
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeTCP(u_char * L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "TCP";
	tcph = (TCP_Header*)(L3payload);

	u_short TCPHeaderLen = (ntohs(tcph->headerlen_rsv_flags) >> 12) * 4;
	if (ntohs(tcph->srcport) == PORT_DNS || ntohs(tcph->dstport) == PORT_DNS)
	{
		decodeDNS(L3payload + TCPHeaderLen);
	}
	else if (ntohs(tcph->srcport) == PORT_HTTP || ntohs(tcph->dstport) == PORT_HTTP)
	{
		int HTTPMsgLen = getL4PayloadLength();
		if (HTTPMsgLen > 0)
		{
			decodeHTTP(L3payload + TCPHeaderLen);
		}

	}
	return 0;
}

/**
*	@brief	����UDP�û����ݱ��ײ����ó�Ա����udph���棬����ԴĿ�˿�ѡ����һ��������
*	@param	L2payload	ָ��UDP�û����ݱ���ָ��
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeUDP(u_char *L3payload)
{
	if (L3payload == NULL)
	{
		return -1;
	}

	protocol = "UDP";
	udph = (UDP_Header*)(L3payload);
	if (ntohs(udph->srcport) == PORT_DNS || ntohs(udph->dstport) == PORT_DNS)
	{
		decodeDNS(L3payload + UDP_HEADER_LENGTH);

	}
	else if ((ntohs(udph->srcport) == PORT_DHCP_CLIENT && ntohs(udph->dstport) == PORT_DHCP_SERVER) || (ntohs(udph->srcport) == PORT_DHCP_SERVER && ntohs(udph->dstport) == PORT_DHCP_CLIENT))
	{
		decodeDHCP(L3payload + UDP_HEADER_LENGTH);
	}
	return 0;
}

/**
*	@brief	����DNS�����ײ����ó�Ա����dnsh����
*	@param	L4payload	ָ��DNS���ĵ�ָ��
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeDNS(u_char * L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "DNS";
	dnsh = (DNS_Header*)(L4payload);
	return 0;
}

/**
*	@brief	����DHCP�����ײ����ó�Ա����dhcph����
*	@param	L4payload	ָ��DHCP���ĵ�ָ��
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeDHCP(u_char * L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "DHCP";
	dhcph = (DHCP_Header*)L4payload;
	return 0;
}

/**
*	@brief	����HTTP�����ײ����ó�Ա����httpmsg����
*	@param	L4payload	ָ��httpmsg���ĵ�ָ��
*	@return	0 ��ʾ�����ɹ�	-1 ��ʾ����ʧ��
*/
int Packet::decodeHTTP(u_char * L4payload)
{
	if (L4payload == NULL)
	{
		return -1;
	}

	protocol = "HTTP";
	httpmsg = L4payload;
	return 0;
}

/**
*	@brief	��ȡIP�ײ�����
*	@param	-
*	@return IP�ײ�����
*/
int Packet::getIPHeaderLegnth() const
{
	if (iph == NULL)
		return -1;
	else
		return (iph->ver_headerlen & 0x0F) * 4;
}

/**
*	@brief	��ȡIP�ײ�����ԭʼֵ
*	@param	-
*	@return IP�ײ�����ԭʼֵ	-1	IP�ײ�Ϊ��
*/
int Packet::getIPHeaderLengthRaw() const
{
	if (iph == NULL)
		return -1;
	else
		return (iph->ver_headerlen & 0x0F);
}

/**
*	@brief	��ȡIP�ײ���־
*	@param	-
*	@return IP�ײ���־	-1	IP�ײ�Ϊ��
*/
int Packet::getIPFlags() const
{
	if (iph == NULL)
		return -1;
	else
		return ntohs(iph->flags_offset) >> 13;
}

/**
*	@brief	��ȡIP�ײ���־DFλ
*	@param	-
*	@return IP�ײ���־DFλ	-1	IP�ײ�Ϊ��
*/
int Packet::getIPFlagDF() const
{
	if (iph == NULL)
		return -1;
	else
		return (ntohs(iph->flags_offset) >> 13) & 0x0001;
}

/**
*	@brief	��ȡIP�ײ���־MFλ
*	@param	-
*	@return IP�ײ���־MFλ	-1	IP�ײ�Ϊ��
*/
int Packet::getIPFlagsMF() const
{
	if (iph == NULL)
		return -1;
	else
		return (ntohs(iph->flags_offset) >> 14) & 0x0001;
}

/**
*	@brief	��ȡIP�ײ�Ƭƫ��
*	@param	-
*	@return IP�ײ�Ƭƫ��	-1	IP�ײ�Ϊ��
*/
int Packet::getIPOffset() const
{
	if (iph == NULL)
		return -1;
	else
		return	ntohs(iph->flags_offset) & 0x1FFF;
}

/**
*	@brief	��ȡICMP�ײ�Other�ֶ��е�Id
*	@param	-
*	@return ICMP�ײ�Other�ֶ��е�Id	-1	ICMP�ײ�Ϊ��
*/
u_short Packet::getICMPID() const
{
	if (icmph == NULL)
		return -1;
	else
		return (u_short)(ntohl(icmph->others) >> 16);
}

/**
*	@brief	��ȡICMP�ײ�Other�ֶ��е�Seq
*	@param	-
*	@return ICMP�ײ�Other�ֶ��е�Seq	-1	ICMP�ײ�Ϊ��
*/
u_short Packet::getICMPSeq() const
{
	if (icmph == NULL)
		return -1;
	else
		return (u_short)(ntohl(icmph->others) & 0x0000FFFF);
}

/**
*	@brief	��ȡTCP�ײ�����
*	@param	-
*	@return TCP�ײ�����	-1	TCP�ײ�Ϊ��
*/
int Packet::getTCPHeaderLength() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 12) * 4;
}

/**
*	@brief	��ȡTCP�ײ�����ԭʼֵ
*	@param	-
*	@return TCP�ײ�����ԭʼֵ	-1	TCP�ײ�Ϊ��
*/
int Packet::getTCPHeaderLengthRaw() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 12);
}

/**
*	@brief	��ȡTCP�ײ���־
*	@param	-
*	@return TCP�ײ���־	-1	TCP�ײ�Ϊ��
*/
u_short Packet::getTCPFlags() const
{
	if (tcph == NULL)
		return -1;
	else
		return  ntohs(tcph->headerlen_rsv_flags) & 0x0FFF;
}

/**
*	@brief	��ȡTCP�ײ���־URG
*	@param	-
*	@return TCP�ײ���־URG	-1	TCP�ײ�Ϊ��
*/
int Packet::getTCPFlagsURG() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 5) & 0x0001;
}

/**
*	@brief	��ȡTCP�ײ���־ACK
*	@param	-
*	@return TCP�ײ���־ACK	-1	TCP�ײ�Ϊ��
*/
int Packet::getTCPFlagsACK() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 4) & 0x0001;
}

/**
*	@brief	��ȡTCP�ײ���־PSH
*	@param	-
*	@return TCP�ײ���־PSH	-1	TCP�ײ�Ϊ��
*/
int Packet::getTCPFlagsPSH() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 3) & 0x0001;
}

/**
*	@brief	��ȡTCP�ײ���־RST
*	@param	-
*	@return TCP�ײ���־RST	-1	TCP�ײ�Ϊ��
*/
int Packet::getTCPFlagsRST() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 2) & 0x0001;
}

/**
*	@brief	��ȡTCP�ײ���־SYN
*	@param	-
*	@return TCP�ײ���־SYN	-1	TCP�ײ�Ϊ��
*/
int Packet::getTCPFlagsSYN() const
{
	if (tcph == NULL)
		return -1;
	else
		return (ntohs(tcph->headerlen_rsv_flags) >> 1) & 0x0001;
}

/**
*	@brief	��ȡTCP�ײ���־FIN
*	@param	-
*	@return TCP�ײ���־FIN	-1	TCP�ײ�Ϊ��
*/
int Packet::getTCPFlagsFIN() const
{
	if (tcph == NULL)
		return -1;
	else
		return ntohs(tcph->headerlen_rsv_flags) & 0x0001;
}
/**
*	@brief ��ȡӦ�ò���Ϣ����
*	@param	-
*	@return Ӧ�ò���Ϣ����
*/
int Packet::getL4PayloadLength() const
{
	if (iph == NULL || tcph == NULL)
	{
		return 0;
	}
	int IPTotalLen = ntohs(iph->totallen);
	int IPHeaderLen = (iph->ver_headerlen & 0x0F) * 4;
	int TCPHeaderLen = (ntohs(tcph->headerlen_rsv_flags) >> 12) * 4;

	return IPTotalLen - IPHeaderLen - TCPHeaderLen;
}

/**
*	@brief	��ȡDNS�ײ���־QR
*	@param	-
*	@return DNS�ײ���־QR	-1	DNS�ײ�Ϊ��
*/
int Packet::getDNSFlagsQR() const
{
	if (dnsh == NULL)
		return -1;
	else
		return	dnsh->flags >> 15;
}

/**
*	@brief	��ȡDNS�ײ���־OPCODE
*	@param	-
*	@return DNS�ײ���־OPCODE	-1	DNS�ײ�Ϊ��
*/
int Packet::getDNSFlagsOPCODE() const
{
	if (dnsh == NULL)
		return -1;
	else
		return	(ntohs(dnsh->flags) >> 11) & 0x000F;
}

/**
*	@brief	��ȡDNS�ײ���־AA
*	@param	-
*	@return DNS�ײ���־AA	-1	DNS�ײ�Ϊ��
*/
int Packet::getDNSFlagsAA() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 10) & 0x0001;
}

/**
*	@brief	��ȡDNS�ײ���־TC
*	@param	-
*	@return DNS�ײ���־TC	-1	DNS�ײ�Ϊ��
*/
int Packet::getDNSFlagsTC() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 9) & 0x0001;
}

/**
*	@brief	��ȡDNS�ײ���־RD
*	@param	-
*	@return DNS�ײ���־RD	-1	DNS�ײ�Ϊ��
*/
int Packet::getDNSFlagsRD() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 8) & 0x0001;
}

/**
*	@brief	��ȡDNS�ײ���־RA
*	@param	-
*	@return DNS�ײ���־RA	-1	DNS�ײ�Ϊ��
*/
int Packet::getDNSFlagsRA() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 7) & 0x0001;
}

/**
*	@brief	��ȡDNS�ײ���־Z
*	@param	-
*	@return DNS�ײ���־Z	-1	DNS�ײ�Ϊ��
*/
int Packet::getDNSFlagsZ() const
{
	if (dnsh == NULL)
		return -1;
	else
		return (ntohs(dnsh->flags) >> 4) & 0x0007;
}

/**
*	@brief	��ȡDNS�ײ���־RCODE
*	@param	-
*	@return DNS�ײ���־RCODE	-1	DNS�ײ�Ϊ��
*/
int Packet::getDNSFlagsRCODE() const
{
	if (dnsh == NULL)
		return -1;
	else
		return ntohs(dnsh->flags) & 0x000F;
}