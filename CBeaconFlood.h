#include "Mac.h"
#include "WirelessPacket.h"
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


class CParam
{
public:
	char * dev;
    char * ssidListFile;

    bool parse(int argc, char* argv[]);
    void usage();
};


class CBeaconFlood
{
private:
	
	pcap_t* pcap;	
    std::vector<std::string> vecSsidList;
    std::vector<u_char*> vecPacketInfo;
    std::vector<u_int8_t> vecPacketLength;
    
    CParam param;
    

public:

	CBeaconFlood(CParam parameter);
	~CBeaconFlood();
    int beaconFlood();

private:


    void readSsidList();
    void makePacket(std::string ssid);
    void sendPacket();    
    void setWirelessPacket(u_char * packet);
    void setTagSsid(u_char * packet, std::string ssid);
    void setTagSupportedRate(u_char * packet);
    void setTagDsParameter(u_char * packet);
    void setTagTrafficIndicationMap(u_char * packet);
    void setTagVenderSpecific(u_char * packet);    
};