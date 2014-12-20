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
	u_char dest_mac[6];					// Ŀ��mac
	u_char src_mac[6];					//Դmac
	u_short ethernet;						//��̫������arp 0x0806
};
struct arp
{
	u_short hardware_type;				//Ӳ������0x0001
	u_short protocol_type;             //Э������0x0800;
	u_char hardware_len;               //Ӳ����ַ����
	u_char protocol_len;					//Э�����ͳ���
	u_short option;                         //����
	u_char src_mac[6];					//Դmac
	u_int src_ip;								//Դip
	u_char dest_mac[6];					//Ŀ��mac	
	u_int dest_ip;							//Դip
	u_char data[18];
};
struct arp_packet
{
	arp_head arp_h;						//ͷ
	arp arp_b;									//��
};
#pragma pack()//ȡ��
u_char *GetSelfMac(char *pDevName);
u_char *BuildPacket(u_char *mac,u_int dest_ip,u_int fake_ip);
