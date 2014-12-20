#include "stdafx.h"
u_char *GetSelfMac(char *pDevName)
{
	static u_char mac[6];
	PACKET_OID_DATA *pod=(PACKET_OID_DATA*)malloc(sizeof(PACKET_OID_DATA)+6);
	pod->Length=6;
	pod->Oid=0x01010102;
	ADAPTER *lpAdapter=PacketOpenAdapter((PCHAR)pDevName);
	if(!lpAdapter)
		{
			printf("ÐáÌ½Ê§°Ü!\n");
			exit(1);
		}
	BOOLEAN	status=PacketRequest(lpAdapter,0,pod);
	if(status)
		{
			memcpy(mac,pod->Data,6);
			PacketCloseAdapter(lpAdapter);
			return mac;
		}
	else
		{
			exit(1);
		}
}