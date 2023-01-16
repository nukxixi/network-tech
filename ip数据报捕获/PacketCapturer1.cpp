#include"pcap.h"
#include<iostream>
#include<stdio.h>
#include<xkeycheck.h>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma pack(1)		//�����ֽڶ��뷽ʽ
typedef struct FrameHeader_t {	//֡�ײ�
	BYTE	DesMAC[6];	// Ŀ�ĵ�ַ+
	BYTE 	SrcMAC[6];	// Դ��ַ+
	WORD	FrameType;	// ֡����
} FrameHeader_t;
typedef struct IPHeader_t {		//IP�ײ�
	BYTE Ver_HLen; //IPЭ��汾��IP�ײ����ȡ���4λΪ�汾����4λΪ�ײ��ĳ���(��λΪ4bytes)
	BYTE TOS;//��������+
	WORD TotalLen;//�ܳ���+
	WORD ID;//��ʶ
	WORD Flag_Segment;//��־ Ƭƫ��
	BYTE TTL;//��������
	BYTE Protocol;//Э��
	WORD Checksum;//ͷ��У���
	u_int SrcIP;//ԴIP
	u_int DstIP;//Ŀ��IP
} IPHeader_t;
typedef struct Data_t {	//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//�ָ�ȱʡ���뷽ʽ

void ip_opreation(const u_char* pktdata) {
	IPHeader_t* IPHeader;
	IPHeader = (IPHeader_t*)(pktdata + 14);
	SOCKADDR_IN source, destination;
	source.sin_addr.s_addr = IPHeader->SrcIP;
	destination.sin_addr.s_addr = IPHeader->DstIP;
	char sourceIP[17];
	char destIP[17];
	inet_ntop(AF_INET, &source.sin_addr, sourceIP, 17);//��������ƽṹ��ASCII���͵ĵ�ַ
	inet_ntop(AF_INET, &destination.sin_addr, destIP, 17);

	printf("\n�汾�ţ�");
	printf("%d", (int)(IPHeader->Ver_HLen >> 4));//ȡ��4λ
	printf("\n�ײ�����:");
	printf("%d", (int)(IPHeader->Ver_HLen & 0xf));//ȡ��4λ
	printf("\n�������ͣ�");
	printf("%d", (int)IPHeader->TOS);
	printf("\n�ܳ��ȣ�");
	printf("%d", (int)ntohs(IPHeader->TotalLen));
	printf("\n��ʶ��0x"); 
	printf("%x", (int)ntohs(IPHeader->ID));
	printf("\n�ֶ�ƫ��:");
	printf("%d", (int)(ntohs(IPHeader->Flag_Segment) & 0x1fff));
	printf("\n����ʱ�䣺");
	printf("%d", (int)IPHeader->TTL);
	printf("\nЭ�����ͣ�");
	if (IPHeader->Protocol == 1) {
		printf("ICMP");
	}
	else if (IPHeader->Protocol == 6) {
		printf("TCP");
	}
	else if (IPHeader->Protocol == 17) {
		printf("UDP");
	}
	printf("\n�ײ�У��ͣ�");
	printf("%d", ntohs(IPHeader->Checksum));
	printf("\nԴIP��ַ��");
	printf("%s", sourceIP);
	printf("\nĿ��IP��ַ��");
	printf("%s", destIP);
}

//�ȷ�������֡
void ethernetoperation(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* pktdata) {

	FrameHeader_t* protocol;//��̫��Э��
	u_short type;			//��̫������
	u_char* Mac;				//��ַ

	//��ȡ��̫����������
	protocol = (FrameHeader_t*)pktdata;
	type = ntohs(protocol->FrameType);

	printf("\n-------------------------------------------------------------------------------------");
	Mac = protocol->DesMAC;
	printf("\nԴMAC��ַ��");
	printf("%02X:%02X:%02X:%02X:%02X:%02X", *Mac, *(Mac + 1), *(Mac + 2), *(Mac + 3), *(Mac + 4), *(Mac + 5));
	Mac = protocol->SrcMAC;
	printf("\nĿ��MAC��ַ��");
	printf("%02x:%02x:%02x:%02x:%02x:%02x", *Mac, *(Mac + 1), *(Mac + 2), *(Mac + 3), *(Mac + 4), *(Mac + 5));

	printf("\n��̫�����ͣ�");
	switch (type)
	{
	case 0x0800:
		printf("IP");
		ip_opreation(pktdata);
		return;
	default:
		printf("����δ֪����");
		return;
	}
	return;
}

int main() {
	pcap_if_t* alldevs; //ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	//pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������

	pcap_t* adhandle;

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

	int idx = 0;
	int dev_idx = 0;
	//��ʾ�ӿ��б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("�豸");
		printf("%d", ++idx);
		printf("%s", d->name);
		printf("%s", d->description);
		printf("\n");
	}

	while (1) {
		printf("\n��ѡ�������豸�ţ�(1-%d)", idx);
		scanf("%d", &dev_idx);
		if (dev_idx<1 || dev_idx>idx) {
			printf("\n��������Ч����");
			continue;
			return -1;
		}
		else
			break;
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
	int count;
	printf("������Ҫ��������ݰ�������");
	scanf("%d", &count);
	pcap_loop(adhandle, count, ethernetoperation, NULL);//ץ��
	pcap_close(adhandle);
	return 0;
}