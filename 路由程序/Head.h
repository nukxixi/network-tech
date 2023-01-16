#pragma once
#include "pcap.h"

#pragma pack(1)//以1byte方式对齐
//报文首部
typedef struct FrameHeader_t {//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

//ARP报文格式
typedef struct ARPFrame_t {//IP首部
	FrameHeader_t FrameHeader;//帧首部
	WORD HardwareType;//硬件类型
	WORD ProtocolType;//协议类型
	BYTE HLen;//硬件地址长度
	BYTE PLen;//协议地址
	WORD Operation;//操作
	BYTE SendHa[6];//发送方MAC
	DWORD SendIP;//发送方IP
	BYTE RecvHa[6];//接收方MAC
	DWORD RecvIP;//接收方IP
}ARPFrame_t;

//IP报文首部
typedef struct IPHeader_t {
	BYTE Ver_HLen; //IP协议版本和IP首部长度。高4位为版本，低4位为首部的长度(单位为4bytes)
	BYTE TOS;//服务类型+
	WORD TotalLen;//总长度+
	WORD ID;//·标识
	WORD Flag_Segment;//标志 片偏移
	BYTE TTL;//生存周期
	BYTE Protocol;//协议
	WORD Checksum;//头部校验和
	u_int SrcIP;//源IP
	u_int DstIP;//目的IP
} IPHeader_t;

typedef struct Data_t {//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;//帧首部
	IPHeader_t IPHeader;//IP首部
}Data_t;

typedef struct ICMP {//包含帧首部和IP首部的数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;
#pragma pack()//恢复4bytes对齐

#pragma pack(1)//以1byte方式对齐
//路由表表项
class routeitem
{
public:
	DWORD net;//目的网络
	DWORD mask;//掩码
	DWORD nextip;//下一跳
	int index;//序号
	bool changeable;//是否可变
	routeitem* nextitem;
	routeitem() { memset(this, 0, sizeof(*this)); }
};
#pragma pack()//恢复4bytes对齐

#pragma pack(1)//恢复4bytes对齐
class routetable
{
public:
	routeitem* head, * tail;
	routetable();//初始化时添加默认项
	void add(routeitem* a);
	void remove(int index);
	void print();
	DWORD search(DWORD ip);
};
#pragma pack()//恢复4bytes对齐

class arptable
{
public:
	DWORD ip;//IP地址
	BYTE mac[6];//MAC地址
	static int num;//表项数量
	static void insert(DWORD ip, BYTE mac[6]);//插入表项
	static int search(DWORD ip, BYTE mac[6]);//删除表项
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

//日志类
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
