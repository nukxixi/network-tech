#include "pcap.h"
#include <iostream>
#include<stdio.h>
#include<cstring>
#include<string>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"packet.lib")
using namespace std;

//报文格式
#pragma pack(1)//以1byte方式对齐
typedef struct FrameHeader_t {//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;
typedef struct ARPFrame_t {//IP首部
	FrameHeader_t FrameHeader;
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址长度
	WORD Operation;//操作类型
	BYTE SendHa[6];//发送方MAC地址
	DWORD SendIP;//发送方IP地址
	BYTE RecvHa[6];//接收方MAC地址
	DWORD RecvIP;//接收方IP地址
}ARPFrame_t;
#pragma pack ()

int main() {
	pcap_if_t* alldevs; //指向设备链表首部的指针
	pcap_if_t* d;
	pcap_addr* a;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	int dev_idx = 0;
	pcap_t* adhandle;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	ARPFrame_t* IPPacket;
	DWORD SendIP;
	DWORD RevIP;

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

	//打印网卡信息和ip
	int idx = 0;  //设备序号
	for (d = alldevs; d != NULL; d = d->next)
	{
		for (a = d->addresses; a != NULL; a = a->next) //获取ip信息
		{
			if (a->addr->sa_family == AF_INET)//判断该地址是否为ip地址
			{
				printf("设备");
				printf("%d", ++idx);
				printf("%s", d->name);
				printf("%s", d->description);
				printf("\n");
				printf("%s%s\n", "IP地址：", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("%s%s\n", "网络掩码:", inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr));
				printf("%s%s\n\n", "广播地址:", inet_ntoa(((struct sockaddr_in*)(a->broadaddr))->sin_addr));
			}
		}
	}

	printf("\n请选择网络设备号：(1-%d)", idx);
	scanf("%d", &dev_idx);
	dev_idx = 1;
	if (dev_idx<1 || dev_idx>idx) {
		printf("\n请输入有效数字");
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

	//模拟远端主机，获取本机接口IP和MAC的对应关系
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//广播
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66; //源MAC地址

	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型:ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型；以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型：IP
	ARPFrame.HLen = 6;//硬件地址长度
	ARPFrame.PLen = 4;//协议地址长度
	ARPFrame.Operation = htons(0x0001);//操作类型为请求

	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x66;
	SendIP = ARPFrame.SendIP = inet_addr("122.122.122.122");
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//目的地址未知
	for (a = d->addresses; a != NULL; a = a->next)//请求的IP地址
	{
		if (a->addr->sa_family == AF_INET)
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}

	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("发送失败\n");
	}

	while (1)//接收响应
	{
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			if (IPPacket->FrameHeader.FrameType == htons(0x806)
				&& IPPacket->Operation == htons(0x0002)
				&& IPPacket->SendIP == ARPFrame.RecvIP)
			{
				printf("本机的MAC地址为:");
				for (int i = 0; i < 5; i++)
				{
					printf("%02X-", IPPacket->FrameHeader.SrcMAC[i]);
				}
				printf("%02X\n\n", IPPacket->FrameHeader.SrcMAC[5]);
				break;
			}
		}
	}

	//获取目的主机的ip和MAC对应关系
	printf("请输入目的主机的IP地址:");
	char ip[15];
	scanf("%s\0", ip);
	RevIP = ARPFrame.RecvIP = inet_addr(ip);
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;

	for (i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("发送失败\n");
	}

	while (1)
	{
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			if (IPPacket->FrameHeader.FrameType == htons(0x806)
				&& IPPacket->Operation == htons(0x2)
				&& IPPacket->SendIP == ARPFrame.RecvIP)
			{
				printf("目的主机的MAC地址为:");
				for (int i = 0; i < 5; i++)
				{
					printf("%02X-", IPPacket->FrameHeader.SrcMAC[i]);
				}
				printf("%02X\n\n", IPPacket->FrameHeader.SrcMAC[5]);
				break;
			}
		}
	}
	return 0;
}