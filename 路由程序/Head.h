#pragma once
#include "pcap.h"

#pragma pack(1)//��1byte��ʽ����
//�����ײ�
typedef struct FrameHeader_t {//֡�ײ�
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;

//ARP���ĸ�ʽ
typedef struct ARPFrame_t {//IP�ײ�
	FrameHeader_t FrameHeader;//֡�ײ�
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ
	WORD Operation;//����
	BYTE SendHa[6];//���ͷ�MAC
	DWORD SendIP;//���ͷ�IP
	BYTE RecvHa[6];//���շ�MAC
	DWORD RecvIP;//���շ�IP
}ARPFrame_t;

//IP�����ײ�
typedef struct IPHeader_t {
	BYTE Ver_HLen; //IPЭ��汾��IP�ײ����ȡ���4λΪ�汾����4λΪ�ײ��ĳ���(��λΪ4bytes)
	BYTE TOS;//��������+
	WORD TotalLen;//�ܳ���+
	WORD ID;//����ʶ
	WORD Flag_Segment;//��־ Ƭƫ��
	BYTE TTL;//��������
	BYTE Protocol;//Э��
	WORD Checksum;//ͷ��У���
	u_int SrcIP;//ԴIP
	u_int DstIP;//Ŀ��IP
} IPHeader_t;

typedef struct Data_t {//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;//֡�ײ�
	IPHeader_t IPHeader;//IP�ײ�
}Data_t;

typedef struct ICMP {//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;
#pragma pack()//�ָ�4bytes����

#pragma pack(1)//��1byte��ʽ����
//·�ɱ����
class routeitem
{
public:
	DWORD net;//Ŀ������
	DWORD mask;//����
	DWORD nextip;//��һ��
	int index;//���
	bool changeable;//�Ƿ�ɱ�
	routeitem* nextitem;
	routeitem() { memset(this, 0, sizeof(*this)); }
};
#pragma pack()//�ָ�4bytes����

#pragma pack(1)//�ָ�4bytes����
class routetable
{
public:
	routeitem* head, * tail;
	routetable();//��ʼ��ʱ���Ĭ����
	void add(routeitem* a);
	void remove(int index);
	void print();
	DWORD search(DWORD ip);
};
#pragma pack()//�ָ�4bytes����

class arptable
{
public:
	DWORD ip;//IP��ַ
	BYTE mac[6];//MAC��ַ
	static int num;//��������
	static void insert(DWORD ip, BYTE mac[6]);//�������
	static int search(DWORD ip, BYTE mac[6]);//ɾ������
}atable[100];

class arpitem
{
public:
	DWORD ip;
	BYTE mac[6];
};

class ipitem
{
public:
	DWORD sip, dip;
	BYTE smac[6], dmac[6];
};

//��־��
class log
{
public:
	char type[5];
	ipitem ip;
	arpitem arp;
	static int num;
	static log diary[100];
	static FILE* fp;
	static void ip_log(Data_t*);
	static void ip_log(const char* a, Data_t*);
	static void arp_log(const char* a, ARPFrame_t* pkt);
	log();
	~log();
};

pcap_if_t* alldevs;
pcap_if_t* d;
pcap_t* ahandle;
pcap_addr* a;
char errbuf[PCAP_ERRBUF_SIZE];

char ip[10][20];
char mask[10][20];
BYTE mymac[6];

void open_devs();
void getMyMac();
void getMac(DWORD ip_, BYTE mac[]);
bool ifMyMac(BYTE mac1[6]);
bool broadMac(BYTE mac[6]);
void trans_pkt(ICMP_t data, BYTE dmac[]);
void setChecksum(Data_t* temp);
bool akChecksum(Data_t* temp);
DWORD WINAPI handlerRequest(LPVOID lparam);
