#include "CMac.h"
#include "CWirelessPacket.h"
#include <iostream>
#include <fstream>
#include <string> 
#include <vector>
#include <map>
#include <utility>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <ncurses.h>

enum status
{
    SUCCESS,
    FAIL,
    NEXT
};


struct ST_PARAM
{
	char * dev;
    char * ssidListFile;
};


class CBeaconFlood
{
private:
	
	pcap_t* pcap;	
    std::vector<std::string> vecSsidList;
    std::vector<u_char*> vecPacketInfo;
    std::vector<u_int8_t> vecPacketLength;
    
    ST_PARAM param;
    

public:

	CBeaconFlood(ST_PARAM parameter);
	~CBeaconFlood();
    int beaconFlood();

private:


    void readSsidList();
    void makePacket(std::string ssid);
    void sendPacket();    
    unsigned long setWirelessPacket(u_char * packet);
    unsigned long setTagSsid(u_char * packet, std::string ssid);
    unsigned long setTagSupportedRate(u_char * packet);
    unsigned long setTagDsParameter(u_char * packet);
    unsigned long setTagTrafficIndicationMap(u_char * packet);
    unsigned long setTagVenderSpecific(u_char * packet);    
};