#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "Head.h"
#include <stdio.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")

log mylog;//日志
int index;//路由表项序号
int device;//设备
int log::num = 0;
log log::diary[100] = {};
FILE* log::fp = nullptr;

int main()
{
	//打开网卡，获取双ip
	open_devs();
	//打印IP
	printf("IP: %s\tMASK: %s\n", ip[0], mask[0]);
	printf("IP: %s\tMASK: %s\n", ip[1], mask[1]);
	//获取本机MAC
	getMyMac();

	int flag;
	routetable rtable;
	DWORD dwThreadId;
	HANDLE hThread = CreateThread(NULL, NULL, handlerRequest, LPVOID(&rtable), 0, &dwThreadId);
	while (1)
	{
		printf("请选择操作：\n");
		printf("1.添加路由表项\n2.删除路由表项\n3.显示路由表\n ");
		scanf("%d", &flag);
		if (flag == 1)
		{
			routeitem item;
			char net[30], mask[30], nextip[30];
			printf("请输入目的网络：");
			scanf("%s", &net);
			item.net = inet_addr(net);
			printf("请输入掩码：");
			scanf("%s", &mask);
			item.mask = inet_addr(mask);
			printf("请输入下一跳步的ip地址：");
			scanf("%s", &nextip);
			item.nextip = inet_addr(nextip);
			item.changeable = true;
			rtable.add(&item);
			printf("成功添加路由表项！\n\n");
		}
		else if (flag == 2)
		{
			printf("请输入删除表项编号：");
			int index;
			scanf("%d", &index);
			rtable.remove(index);
		}
		else if (flag == 3)
		{
			rtable.print();
		}
		else {
			printf("无效操作，请重新选择\n");
		}
	}
	system("pause");
	return 0;
}

void open_devs()	//打开网卡，获取双ip
{
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		//错误处理
		printf("\n获得本机设备列表失败");
		pcap_freealldevs(alldevs);
		return;
	}
	else
	{
		int idx = 0;
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
			scanf("%d", &device);
			if (device<1 || device>idx) {
				printf("\n请输入有效数字");
				continue;
			}
			else
				break;
		}

		int i = 0, m = 0;
		for (d = alldevs; i < device - 1; d = d->next, i++);
		for (a = d->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)//判断该地址是否为ip地址
			{
				//将对应第device块网卡的内容存入全局数组
				strcpy(ip[m], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				strcpy(mask[m], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				m++;
			}
		}
		//打开设备
		if ((ahandle = pcap_open(d->name,          // 设备名
			65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
			PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
			100,             // 读取超时时间
			NULL,             // 远程机器验证
			errbuf            // 错误缓冲池
		)) == NULL)
		{
			printf("\n无法打开设备");
			printf(errbuf);
			pcap_freealldevs(alldevs);
		}
	}
}

bool ifMyMac(BYTE mac1[6])
{
	for (int i = 0; i < 6; i++) {
		if (mac1[i] != mymac[i])
			return false;
	}
	return true;
}

bool broadMac(BYTE mac[6])
{
	for (int i = 0; i < 6; i++) {
		if (mac[i] != 0xff)
			return false;
	}
	return true;
}


void getMyMac()//伪造ARP报文获取本机MAC
{
	memset(mymac, 0, sizeof(mymac));
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66; //源MAC地址

	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求

	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x66;
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//目的地址未知

	for (a = d->addresses; a != NULL; a = a->next)//请求的IP地址
	{
		if (a->addr->sa_family == AF_INET)
		{
			ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	mylog.arp_log("发送", &ARPFrame);

	if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("发送失败\n");
	}
	else
	{
		while (1)
		{
			pcap_pkthdr* pkt_header;
			const u_char* pkt_data;
			//接收响应
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			if (rtn == 1)
			{
				ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->FrameHeader.FrameType == htons(0x806)
					&& IPPacket->Operation == htons(0x0002)
					&& IPPacket->SendIP == ARPFrame.RecvIP)//接收到响应包
				{
					mylog.arp_log("接收",IPPacket);
					printf("本机的MAC地址为: ");
					for (int i = 0; i < 5; i++)
					{
						printf("%02X-", IPPacket->FrameHeader.SrcMAC[i]);
					}
					printf("%02X\n\n", IPPacket->FrameHeader.SrcMAC[5]);
					for (int i = 0; i < 6; i++)
						mymac[i] = IPPacket->FrameHeader.SrcMAC[i];
					break;
				}

			}
		}
	}
}

void getMac(DWORD dip, BYTE mac[])//获取目的ip对应的mac
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = mymac[i];
		ARPFrame.SendHa[i] = mymac[i];
	}

	ARPFrame.FrameHeader.FrameType = htons(0x806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4;//协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求

	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(ip[0]);
	//将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	//将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = dip;
	mylog.arp_log("发送", &ARPFrame);


	if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("发送失败\n");
	}
	else
	{
		while (1)
		{
			pcap_pkthdr* pkt_header;
			const u_char* pkt_data;
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			if (rtn == 1)
			{
				ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->FrameHeader.FrameType == htons(0x806)
					&& IPPacket->Operation == htons(0x0002)
					&& IPPacket->SendIP == ARPFrame.RecvIP)
				{
					mylog.arp_log("接收",IPPacket);
					for (int i = 0; i < 6; i++)
						mac[i] = IPPacket->FrameHeader.SrcMAC[i];
					break;
				}
			}
		}
	}
}

void routetable::add(routeitem* item)//添加路由表项
{
	if (item->changeable == false)//添加默认路由表项，添加到开头
	{
		item->nextitem = head->nextitem;
		head->nextitem = item;
		item->changeable = false;
	}
	else
	{
		//手动添加的表项，找到插入的位置，按照掩码由长到短添加
		routeitem* p1 = head->nextitem;
		while (p1->nextitem != tail)
		{
			if (item->mask < item->mask >= p1->nextitem->mask && p1->mask)
				break;
			p1 = p1->nextitem;
		}
		//插入
		item->nextitem = p1->nextitem;
		p1->nextitem = item;
	}
	routeitem* p2 = head->nextitem;
	for (int i = 0; p2 != tail; p2 = p2->nextitem, i++)//设置路由表项的序号
	{
		p2->index = i + 1;
	}
}

void routetable::remove(int index)//删除路由表项
{
	routeitem* p1 = head;
	while (p1->nextitem != tail)
	{
		if (p1->nextitem->index == index)
		{
			if (!p1->nextitem->changeable)//无法删除默认路由表项
			{
				printf("默认路由表项不可删除！\n");
				return;
			}
			else
			{
				p1->nextitem = p1->nextitem->nextitem;
				return;
			}
		}
		p1 = p1->nextitem;
	}
	printf("请输入正确的序号！\n");
}

void routetable::print()//打印路由表
{
	routeitem* p = head->nextitem;
	while (p != tail)
	{
		in_addr addr;
		char* output;
		printf("%d   ", p->index);

		addr.s_addr = p->net;
		output = inet_ntoa(addr);
		printf("%s\t", output);

		addr.s_addr = p->mask;
		output = inet_ntoa(addr);
		printf("%s\t", output);

		addr.s_addr = p->nextip;
		output = inet_ntoa(addr);
		printf("%s\n", output);

		p = p->nextitem;
	}
	printf("\n");
}

//查找路由表项，返回下一跳步
DWORD routetable::search(DWORD ip)
{
	routeitem* p = head->nextitem;
	while (p != tail) {
		if ((p->mask & ip) == p->net)
			return p->nextip;
		p = p->nextitem;
	}
	return -1;
}

routetable::routetable()//初始化，添加默认表项
{
	head = new routeitem;
	tail = new routeitem;
	head->nextitem = tail;
	//添加默认路由表项
	routeitem* item1 = new routeitem;
	item1->net = (inet_addr(ip[0])) & (inet_addr(mask[0]));	//本机网卡的ip和掩码按位与，得到目的网络
	item1->mask = inet_addr(mask[0]);
	item1->changeable = false;
	this->add(item1);//添加表项

	routeitem* item2 = new routeitem;
	item2->net = (inet_addr(ip[1])) & (inet_addr(mask[1]));
	item2->mask = inet_addr(mask[1]);
	item2->changeable = false;
	this->add(item2);
}

void trans_pkt(ICMP_t pkt_data, BYTE mac[]) //转发数据报的函数
{
	Data_t* pkt = (Data_t*)&pkt_data;
	memcpy(pkt->FrameHeader.SrcMAC, pkt->FrameHeader.DesMAC, 6); //源MAC为本机MAC
	memcpy(pkt->FrameHeader.DesMAC, mac, 6); //目的MAC为下一跳MAC
	pkt->IPHeader.TTL--; 
	if (pkt->IPHeader.TTL < 0)//丢弃
		return;
	setChecksum(pkt); //重新设置校验和
	int rtn = pcap_sendpacket(ahandle, (const u_char*)pkt, sizeof(ICMP_t)); //发送数据报
	if (rtn == 0)
		mylog.ip_log("转发", pkt); //写入日志
}

DWORD WINAPI handlerRequest(LPVOID lparam)//接收线程函数
{
	routetable rtable = *(routetable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			if (rtn)//接收到消息
				break;
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (ifMyMac(header->DesMAC))//目的mac等于自己的mac
		{
			if (ntohs(header->FrameType) == 0x800)//IP格式数据报
			{
				Data_t* data = (Data_t*)pkt_data;
				mylog.ip_log("接收", data);//写入日志
				//在路由表中查找有没有目的网络相同的表项
				DWORD dst_ip = data->IPHeader.DstIP;
				DWORD rlt_ip = rtable.search(dst_ip);
				if (rlt_ip == -1)//路由表中没有，丢弃该包
					continue;
				if (akChecksum(data))//检验校验和
				{
					if (!broadMac(data->FrameHeader.DesMAC))//不是广播
					{
						//ICMP报文包含IP数据包报头和其它内容
						ICMP_t* temp_ = (ICMP_t*)pkt_data;
						ICMP_t temp = *temp_;
						BYTE mac[6];

						if (rlt_ip == 0)
						{
							//如果ARP表中没有所需内容，则需要获取ARP
							if (!arptable::search(dst_ip, mac))
								arptable::insert(dst_ip, mac);
							trans_pkt(temp, mac);
						}
						else if (rlt_ip > 0 )//非直接投递，查找下一跳IP的MAC
						{
							if (!arptable::search(rlt_ip, mac))
								arptable::insert(rlt_ip, mac);
							trans_pkt(temp, mac);
						}
					}
				}
			}
		}
	}
}


log::log()
{
	fp = fopen("log.txt", "a+"); //a+方式打开文件
}

log::~log()
{
	fclose(fp);
}

void log::ip_log(Data_t* pkt)//ip类型
{
	strcpy(diary[num % 100].type, "IP");
	diary[num % 100].ip.sip = pkt->IPHeader.SrcIP;
	diary[num % 100].ip.dip = pkt->IPHeader.DstIP;
	memcpy(diary[num % 100].ip.smac, pkt->FrameHeader.SrcMAC, 6);
	memcpy(diary[num % 100].ip.dmac, pkt->FrameHeader.DesMAC, 6);
}

void log::ip_log(const char* a, Data_t* pkt)//ip类型
{
	fprintf(fp, "IP  ");
	fprintf(fp, a);
	fprintf(fp, "  ");

	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* output = inet_ntoa(addr);

	fprintf(fp, "源IP： ");
	fprintf(fp, "%s  ", output);
	fprintf(fp, "目的IP： ");
	addr.s_addr = pkt->IPHeader.DstIP;
	fprintf(fp, "%s  ", output);
	fprintf(fp, "源MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "目的MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);
}

void log::arp_log(const char* a, ARPFrame_t* pkt)//arp类型
{
	fprintf(fp, "ARP ");
	fprintf(fp, a);
	fprintf(fp, "  ");
	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* output = inet_ntoa(addr);
	fprintf(fp, "IP： ");
	fprintf(fp, "%s  ", output);
	fprintf(fp, "MAC： ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);
}

void setChecksum(Data_t* temp)//设置校验和
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* data = (WORD*)&temp->IPHeader;
	for (int i = 0; i < 10; i++)//16bit一组，共10组
	{
		sum += data[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//取反
}

bool akChecksum(Data_t* temp)//检验校验和
{
	unsigned int sum = 0;
	WORD* data = (WORD*)&temp->IPHeader;
	for (int i = 0; i < 10; i++) //包含原有校验和字段
	{
		sum += data[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum += s;
		}
	}
	if (sum == 65535)
		return true;
	return false;
}

int arptable::num = 0;
void arptable::insert(DWORD ip, BYTE mac[6])
{
	atable[num].ip = ip;
	getMac(ip, atable[num].mac);
	memcpy(mac, atable[num].mac, 6);
	num++;
}
int arptable::search(DWORD ip, BYTE mac[6])
{
	memset(mac, 0, 6);
	for (int i = 0; i < num; i++)
	{
		if (ip == atable[i].ip)
		{
			memcpy(mac, atable[i].mac, 6);
			return 1;
		}
	}
	return 0;
}