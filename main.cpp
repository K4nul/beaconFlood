#include "CBeaconFlood.h"
#include <iostream>
#include <string>

// 요구사항 
/***
1. ssid-list-file을 읽어온다 
	- vector 
2. Radiotab haeder를 만든다 
3. beacon frame을 만든다 
4. wireless manager를 만든다 
	- ssid 길이 측정 
	- ssid 가변 길이 
5. 패킷을 합친다 
	- 합쳐진 패킷이 필요 
6. 패킷 전송 (FF:FF:FF:FF:FF:FF)
***/

void usage() 
{
	printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
	printf("sample : beacon-flood mon0 ssid-list.txt");
}

bool parse(int argc, char* argv[], ST_PARAM &parameter) 
{
	if (argc != 3) {
		usage();
		return false;
	}
	parameter.dev = argv[1];
	parameter.ssidListFile = argv[2];

	return true;
}

int main(int argc, char* argv[]) 
{
	ST_PARAM parameter;
	if (!parse(argc, argv, parameter))
		return -1;

	CBeaconFlood CBeaconFlood(parameter);
	CBeaconFlood.beaconFlood();

	return 0;
}
