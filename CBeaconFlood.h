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
    std::vector<const u_char*> packetInfo;
    ST_PARAM param;
    

public:

	CBeaconFlood(ST_PARAM parameter);
	~CBeaconFlood();
    int beaconFlood();

private:


    void readSsidList();
    void makePacket();
    void sendPacket();    
};