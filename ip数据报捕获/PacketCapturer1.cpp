#include"pcap.h"
#include<iostream>
#include<stdio.h>
#include<xkeycheck.h>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t {	//帧首部
	BYTE	DesMAC[6];	// 目的地址+
	BYTE 	SrcMAC[6];	// 源地址+
	WORD	FrameType;	// 帧类型
} FrameHeader_t;
typedef struct IPHeader_t {		//IP首部
	BYTE Ver_HLen; //IP协议版本和IP首部长度。高4位为版本，低4位为首部的长度(单位为4bytes)
	BYTE TOS;//服务类型+
	WORD TotalLen;//总长度+
	WORD ID;//标识
	WORD Flag_Segment;//标志 片偏移
	BYTE TTL;//生存周期
	BYTE Protocol;//协议
	WORD Checksum;//头部校验和
	u_int SrcIP;//源IP
	u_int DstIP;//目的IP
} IPHeader_t;
typedef struct Data_t {	//包含帧首部和IP首部的数据包
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//恢复缺省对齐方式

void ip_opreation(const u_char* pktdata) {
	IPHeader_t* IPHeader;
	IPHeader = (IPHeader_t*)(pktdata + 14);
	SOCKADDR_IN source, destination;
	source.sin_addr.s_addr = IPHeader->SrcIP;
	destination.sin_addr.s_addr = IPHeader->DstIP;
	char sourceIP[17];
	char destIP[17];
	inet_ntop(AF_INET, &source.sin_addr, sourceIP, 17);//网络二进制结构到ASCII类型的地址
	inet_ntop(AF_INET, &destination.sin_addr, destIP, 17);

	printf("\n版本号：");
	printf("%d", (int)(IPHeader->Ver_HLen >> 4));//取高4位
	printf("\n首部长度:");
	printf("%d", (int)(IPHeader->Ver_HLen & 0xf));//取低4位
	printf("\n服务类型：");
	printf("%d", (int)IPHeader->TOS);
	printf("\n总长度：");
	printf("%d", (int)ntohs(IPHeader->TotalLen));
	printf("\n标识：0x"); 
	printf("%x", (int)ntohs(IPHeader->ID));
	printf("\n分段偏移:");
	printf("%d", (int)(ntohs(IPHeader->Flag_Segment) & 0x1fff));
	printf("\n生存时间：");
	printf("%d", (int)IPHeader->TTL);
	printf("\n协议类型：");
	if (IPHeader->Protocol == 1) {
		printf("ICMP");
	}
	else if (IPHeader->Protocol == 6) {
		printf("TCP");
	}
	else if (IPHeader->Protocol == 17) {
		printf("UDP");
	}
	printf("\n首部校验和：");
	printf("%d", ntohs(IPHeader->Checksum));
	printf("\n源IP地址：");
	printf("%s", sourceIP);
	printf("\n目的IP地址：");
	printf("%s", destIP);
}

//先分析物理帧
void ethernetoperation(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* pktdata) {

	FrameHeader_t* protocol;//以太网协议
	u_short type;			//以太网类型
	u_char* Mac;				//地址

	//获取以太网数据内容
	protocol = (FrameHeader_t*)pktdata;
	type = ntohs(protocol->FrameType);

	printf("\n-------------------------------------------------------------------------------------");
	Mac = protocol->DesMAC;
	printf("\n源MAC地址：");
	printf("%02X:%02X:%02X:%02X:%02X:%02X", *Mac, *(Mac + 1), *(Mac + 2), *(Mac + 3), *(Mac + 4), *(Mac + 5));
	Mac = protocol->SrcMAC;
	printf("\n目的MAC地址：");
	printf("%02x:%02x:%02x:%02x:%02x:%02x", *Mac, *(Mac + 1), *(Mac + 2), *(Mac + 3), *(Mac + 4), *(Mac + 5));

	printf("\n以太网类型：");
	switch (type)
	{
	case 0x0800:
		printf("IP");
		ip_opreation(pktdata);
		return;
	default:
		printf("其他未知类型");
		return;
	}
	return;
}

int main() {
	pcap_if_t* alldevs; //指向设备链表首部的指针
	pcap_if_t* d;
	//pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区

	pcap_t* adhandle;

	//获得本机的设备列表
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		//错误处理
		printf("\n获得本机设备列表失败");
		pcap_freealldevs(alldevs);
		return -1;
	}

	int idx = 0;
	int dev_idx = 0;
	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("设备");
		printf("%d", ++idx);
		printf("%s", d->name);
		printf("%s", d->description);
		printf("\n");
	}

	while (1) {
		printf("\n请选择网络设备号：(1-%d)", idx);
		scanf("%d", &dev_idx);
		if (dev_idx<1 || dev_idx>idx) {
			printf("\n请输入有效数字");
			continue;
			return -1;
		}
		else
			break;
	}
	int i = 0;
	for (d = alldevs; i < dev_idx - 1; d = d->next, i++);

	//打开设备
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		printf("\n无法打开设备");
		for (int i = 0; i < strlen(errbuf); i++) {
			std::cout << errbuf[i];
		}
		pcap_freealldevs(alldevs);
		return -1;
	}
	pcap_freealldevs(alldevs);
	int count;
	printf("请输入要捕获的数据包个数：");
	scanf("%d", &count);
	pcap_loop(adhandle, count, ethernetoperation, NULL);//抓包
	pcap_close(adhandle);
	return 0;
}