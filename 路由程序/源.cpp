#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "Head.h"
#include <stdio.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")

log mylog;//��־
int index;//·�ɱ������
int device;//�豸
int log::num = 0;
log log::diary[100] = {};
FILE* log::fp = nullptr;

int main()
{
	//����������ȡ˫ip
	open_devs();
	//��ӡIP
	printf("IP: %s\tMASK: %s\n", ip[0], mask[0]);
	printf("IP: %s\tMASK: %s\n", ip[1], mask[1]);
	//��ȡ����MAC
	getMyMac();

	int flag;
	routetable rtable;
	DWORD dwThreadId;
	HANDLE hThread = CreateThread(NULL, NULL, handlerRequest, LPVOID(&rtable), 0, &dwThreadId);
	while (1)
	{
		printf("��ѡ�������\n");
		printf("1.���·�ɱ���\n2.ɾ��·�ɱ���\n3.��ʾ·�ɱ�\n ");
		scanf("%d", &flag);
		if (flag == 1)
		{
			routeitem item;
			char net[30], mask[30], nextip[30];
			printf("������Ŀ�����磺");
			scanf("%s", &net);
			item.net = inet_addr(net);
			printf("���������룺");
			scanf("%s", &mask);
			item.mask = inet_addr(mask);
			printf("��������һ������ip��ַ��");
			scanf("%s", &nextip);
			item.nextip = inet_addr(nextip);
			item.changeable = true;
			rtable.add(&item);
			printf("�ɹ����·�ɱ��\n\n");
		}
		else if (flag == 2)
		{
			printf("������ɾ�������ţ�");
			int index;
			scanf("%d", &index);
			rtable.remove(index);
		}
		else if (flag == 3)
		{
			rtable.print();
		}
		else {
			printf("��Ч������������ѡ��\n");
		}
	}
	system("pause");
	return 0;
}

void open_devs()	//����������ȡ˫ip
{
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf			      //������Ϣ���滺����
	) == -1)
	{
		//������
		printf("\n��ñ����豸�б�ʧ��");
		pcap_freealldevs(alldevs);
		return;
	}
	else
	{
		int idx = 0;
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
			scanf("%d", &device);
			if (device<1 || device>idx) {
				printf("\n��������Ч����");
				continue;
			}
			else
				break;
		}

		int i = 0, m = 0;
		for (d = alldevs; i < device - 1; d = d->next, i++);
		for (a = d->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET)//�жϸõ�ַ�Ƿ�Ϊip��ַ
			{
				//����Ӧ��device�����������ݴ���ȫ������
				strcpy(ip[m], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				strcpy(mask[m], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				m++;
			}
		}
		//���豸
		if ((ahandle = pcap_open(d->name,          // �豸��
			65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
			PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
			100,             // ��ȡ��ʱʱ��
			NULL,             // Զ�̻�����֤
			errbuf            // ���󻺳��
		)) == NULL)
		{
			printf("\n�޷����豸");
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


void getMyMac()//α��ARP���Ļ�ȡ����MAC
{
	memset(mymac, 0, sizeof(mymac));
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66; //ԴMAC��ַ

	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����

	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x66;
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//Ŀ�ĵ�ַδ֪

	for (a = d->addresses; a != NULL; a = a->next)//�����IP��ַ
	{
		if (a->addr->sa_family == AF_INET)
		{
			ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	mylog.arp_log("����", &ARPFrame);

	if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("����ʧ��\n");
	}
	else
	{
		while (1)
		{
			pcap_pkthdr* pkt_header;
			const u_char* pkt_data;
			//������Ӧ
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			if (rtn == 1)
			{
				ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->FrameHeader.FrameType == htons(0x806)
					&& IPPacket->Operation == htons(0x0002)
					&& IPPacket->SendIP == ARPFrame.RecvIP)//���յ���Ӧ��
				{
					mylog.arp_log("����",IPPacket);
					printf("������MAC��ַΪ: ");
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

void getMac(DWORD dip, BYTE mac[])//��ȡĿ��ip��Ӧ��mac
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = mymac[i];
		ARPFrame.SendHa[i] = mymac[i];
	}

	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����

	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr(ip[0]);
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = dip;
	mylog.arp_log("����", &ARPFrame);


	if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("����ʧ��\n");
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
					mylog.arp_log("����",IPPacket);
					for (int i = 0; i < 6; i++)
						mac[i] = IPPacket->FrameHeader.SrcMAC[i];
					break;
				}
			}
		}
	}
}

void routetable::add(routeitem* item)//���·�ɱ���
{
	if (item->changeable == false)//���Ĭ��·�ɱ����ӵ���ͷ
	{
		item->nextitem = head->nextitem;
		head->nextitem = item;
		item->changeable = false;
	}
	else
	{
		//�ֶ���ӵı���ҵ������λ�ã����������ɳ��������
		routeitem* p1 = head->nextitem;
		while (p1->nextitem != tail)
		{
			if (item->mask < item->mask >= p1->nextitem->mask && p1->mask)
				break;
			p1 = p1->nextitem;
		}
		//����
		item->nextitem = p1->nextitem;
		p1->nextitem = item;
	}
	routeitem* p2 = head->nextitem;
	for (int i = 0; p2 != tail; p2 = p2->nextitem, i++)//����·�ɱ�������
	{
		p2->index = i + 1;
	}
}

void routetable::remove(int index)//ɾ��·�ɱ���
{
	routeitem* p1 = head;
	while (p1->nextitem != tail)
	{
		if (p1->nextitem->index == index)
		{
			if (!p1->nextitem->changeable)//�޷�ɾ��Ĭ��·�ɱ���
			{
				printf("Ĭ��·�ɱ����ɾ����\n");
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
	printf("��������ȷ����ţ�\n");
}

void routetable::print()//��ӡ·�ɱ�
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

//����·�ɱ��������һ����
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

routetable::routetable()//��ʼ�������Ĭ�ϱ���
{
	head = new routeitem;
	tail = new routeitem;
	head->nextitem = tail;
	//���Ĭ��·�ɱ���
	routeitem* item1 = new routeitem;
	item1->net = (inet_addr(ip[0])) & (inet_addr(mask[0]));	//����������ip�����밴λ�룬�õ�Ŀ������
	item1->mask = inet_addr(mask[0]);
	item1->changeable = false;
	this->add(item1);//��ӱ���

	routeitem* item2 = new routeitem;
	item2->net = (inet_addr(ip[1])) & (inet_addr(mask[1]));
	item2->mask = inet_addr(mask[1]);
	item2->changeable = false;
	this->add(item2);
}

void trans_pkt(ICMP_t pkt_data, BYTE mac[]) //ת�����ݱ��ĺ���
{
	Data_t* pkt = (Data_t*)&pkt_data;
	memcpy(pkt->FrameHeader.SrcMAC, pkt->FrameHeader.DesMAC, 6); //ԴMACΪ����MAC
	memcpy(pkt->FrameHeader.DesMAC, mac, 6); //Ŀ��MACΪ��һ��MAC
	pkt->IPHeader.TTL--; 
	if (pkt->IPHeader.TTL < 0)//����
		return;
	setChecksum(pkt); //��������У���
	int rtn = pcap_sendpacket(ahandle, (const u_char*)pkt, sizeof(ICMP_t)); //�������ݱ�
	if (rtn == 0)
		mylog.ip_log("ת��", pkt); //д����־
}

DWORD WINAPI handlerRequest(LPVOID lparam)//�����̺߳���
{
	routetable rtable = *(routetable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			if (rtn)//���յ���Ϣ
				break;
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (ifMyMac(header->DesMAC))//Ŀ��mac�����Լ���mac
		{
			if (ntohs(header->FrameType) == 0x800)//IP��ʽ���ݱ�
			{
				Data_t* data = (Data_t*)pkt_data;
				mylog.ip_log("����", data);//д����־
				//��·�ɱ��в�����û��Ŀ��������ͬ�ı���
				DWORD dst_ip = data->IPHeader.DstIP;
				DWORD rlt_ip = rtable.search(dst_ip);
				if (rlt_ip == -1)//·�ɱ���û�У������ð�
					continue;
				if (akChecksum(data))//����У���
				{
					if (!broadMac(data->FrameHeader.DesMAC))//���ǹ㲥
					{
						//ICMP���İ���IP���ݰ���ͷ����������
						ICMP_t* temp_ = (ICMP_t*)pkt_data;
						ICMP_t temp = *temp_;
						BYTE mac[6];

						if (rlt_ip == 0)
						{
							//���ARP����û���������ݣ�����Ҫ��ȡARP
							if (!arptable::search(dst_ip, mac))
								arptable::insert(dst_ip, mac);
							trans_pkt(temp, mac);
						}
						else if (rlt_ip > 0 )//��ֱ��Ͷ�ݣ�������һ��IP��MAC
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
	fp = fopen("log.txt", "a+"); //a+��ʽ���ļ�
}

log::~log()
{
	fclose(fp);
}

void log::ip_log(Data_t* pkt)//ip����
{
	strcpy(diary[num % 100].type, "IP");
	diary[num % 100].ip.sip = pkt->IPHeader.SrcIP;
	diary[num % 100].ip.dip = pkt->IPHeader.DstIP;
	memcpy(diary[num % 100].ip.smac, pkt->FrameHeader.SrcMAC, 6);
	memcpy(diary[num % 100].ip.dmac, pkt->FrameHeader.DesMAC, 6);
}

void log::ip_log(const char* a, Data_t* pkt)//ip����
{
	fprintf(fp, "IP  ");
	fprintf(fp, a);
	fprintf(fp, "  ");

	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* output = inet_ntoa(addr);

	fprintf(fp, "ԴIP�� ");
	fprintf(fp, "%s  ", output);
	fprintf(fp, "Ŀ��IP�� ");
	addr.s_addr = pkt->IPHeader.DstIP;
	fprintf(fp, "%s  ", output);
	fprintf(fp, "ԴMAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "Ŀ��MAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);
}

void log::arp_log(const char* a, ARPFrame_t* pkt)//arp����
{
	fprintf(fp, "ARP ");
	fprintf(fp, a);
	fprintf(fp, "  ");
	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* output = inet_ntoa(addr);
	fprintf(fp, "IP�� ");
	fprintf(fp, "%s  ", output);
	fprintf(fp, "MAC�� ");
	for (int i = 0; i < 5; i++)
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	fprintf(fp, "%02X\n", pkt->SendHa[5]);
}

void setChecksum(Data_t* temp)//����У���
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* data = (WORD*)&temp->IPHeader;
	for (int i = 0; i < 10; i++)//16bitһ�飬��10��
	{
		sum += data[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//ȡ��
}

bool akChecksum(Data_t* temp)//����У���
{
	unsigned int sum = 0;
	WORD* data = (WORD*)&temp->IPHeader;
	for (int i = 0; i < 10; i++) //����ԭ��У����ֶ�
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