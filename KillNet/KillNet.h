#define HAVE_REMOTE
#include "pcap.h"
#include "remote-ext.h"
#include "packet32.h"
#include "windows.h"
#include "iostream"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
using namespace std;
#pragma pack(1)
struct arp_head
{
	u_char dest_mac[6];					// 目的mac
	u_char src_mac[6];					//源mac
	u_short ethernet;						//以太网类型arp 0x0806
};
struct arp
{
	u_short hardware_type;				//硬件类型0x0001
	u_short protocol_type;             //协议类型0x0800;
	u_char hardware_len;               //硬件地址长度
	u_char protocol_len;					//协议类型长度
	u_short option;                         //操作
	u_char src_mac[6];					//源mac
	u_int src_ip;								//源ip
	u_char dest_mac[6];					//目的mac	
	u_int dest_ip;							//源ip
	u_char data[18];
};
struct arp_packet
{
	arp_head arp_h;						//头
	arp arp_b;									//体
};
#pragma pack()//取消
u_char *GetSelfMac(char *pDevName);
u_char *BuildPacket(u_char *mac,u_int dest_ip,u_int fake_ip);
