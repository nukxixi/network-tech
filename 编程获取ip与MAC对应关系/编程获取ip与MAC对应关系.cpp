#include "pcap.h"
#include <iostream>
#include<stdio.h>
#include<cstring>
#include<string>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"packet.lib")
using namespace std;

//���ĸ�ʽ
#pragma pack(1)//��1byte��ʽ����
typedef struct FrameHeader_t {//֡�ײ�
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;
typedef struct ARPFrame_t {//IP�ײ�
	FrameHeader_t FrameHeader;
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ����
	WORD Operation;//��������
	BYTE SendHa[6];//���ͷ�MAC��ַ
	DWORD SendIP;//���ͷ�IP��ַ
	BYTE RecvHa[6];//���շ�MAC��ַ
	DWORD RecvIP;//���շ�IP��ַ
}ARPFrame_t;
#pragma pack ()

int main() {
	pcap_if_t* alldevs; //ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	pcap_addr* a;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	int dev_idx = 0;
	pcap_t* adhandle;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	ARPFrame_t* IPPacket;
	DWORD SendIP;
	DWORD RevIP;

	//��ñ������豸�б�
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf			      //������Ϣ���滺����
	) == -1)
	{
		//������
		printf("\n��ñ����豸�б�ʧ��");
		pcap_freealldevs(alldevs);
		return -1;
	}

	//��ӡ������Ϣ��ip
	int idx = 0;  //�豸���
	for (d = alldevs; d != NULL; d = d->next)
	{
		for (a = d->addresses; a != NULL; a = a->next) //��ȡip��Ϣ
		{
			if (a->addr->sa_family == AF_INET)//�жϸõ�ַ�Ƿ�Ϊip��ַ
			{
				printf("�豸");
				printf("%d", ++idx);
				printf("%s", d->name);
				printf("%s", d->description);
				printf("\n");
				printf("%s%s\n", "IP��ַ��", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("%s%s\n", "��������:", inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr));
				printf("%s%s\n\n", "�㲥��ַ:", inet_ntoa(((struct sockaddr_in*)(a->broadaddr))->sin_addr));
			}
		}
	}

	printf("\n��ѡ�������豸�ţ�(1-%d)", idx);
	scanf("%d", &dev_idx);
	dev_idx = 1;
	if (dev_idx<1 || dev_idx>idx) {
		printf("\n��������Ч����");
	}

	int i = 0;
	for (d = alldevs; i < dev_idx - 1; d = d->next, i++);

	//���豸
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
	)) == NULL)
	{
		printf("\n�޷����豸");
		for (int i = 0; i < strlen(errbuf); i++) {
			std::cout << errbuf[i];
		}
		pcap_freealldevs(alldevs);
		return -1;
	}
	pcap_freealldevs(alldevs);

	//ģ��Զ����������ȡ�����ӿ�IP��MAC�Ķ�Ӧ��ϵ
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//�㲥
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66; //ԴMAC��ַ

	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����:ARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ�����ͣ���̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э�����ͣ�IP
	ARPFrame.HLen = 6;//Ӳ����ַ����
	ARPFrame.PLen = 4;//Э���ַ����
	ARPFrame.Operation = htons(0x0001);//��������Ϊ����

	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x66;
	SendIP = ARPFrame.SendIP = inet_addr("122.122.122.122");
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//Ŀ�ĵ�ַδ֪
	for (a = d->addresses; a != NULL; a = a->next)//�����IP��ַ
	{
		if (a->addr->sa_family == AF_INET)
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}

	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("����ʧ��\n");
	}

	while (1)//������Ӧ
	{
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			if (IPPacket->FrameHeader.FrameType == htons(0x806)
				&& IPPacket->Operation == htons(0x0002)
				&& IPPacket->SendIP == ARPFrame.RecvIP)
			{
				printf("������MAC��ַΪ:");
				for (int i = 0; i < 5; i++)
				{
					printf("%02X-", IPPacket->FrameHeader.SrcMAC[i]);
				}
				printf("%02X\n\n", IPPacket->FrameHeader.SrcMAC[5]);
				break;
			}
		}
	}

	//��ȡĿ��������ip��MAC��Ӧ��ϵ
	printf("������Ŀ��������IP��ַ:");
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
		printf("����ʧ��\n");
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
				printf("Ŀ��������MAC��ַΪ:");
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