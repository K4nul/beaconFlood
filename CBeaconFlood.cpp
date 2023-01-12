#include "CBeaconFlood.h"

CBeaconFlood::CBeaconFlood(ST_PARAM parameter) : param(parameter)
{
	// char errbuf[PCAP_ERRBUF_SIZE];
	// pcap = pcap_open_live(param.dev, 0, 0, 0, errbuf);
	// if (pcap == NULL) {
	// 	fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev, errbuf);
    //     exit(1);
	// }

}

CBeaconFlood::~CBeaconFlood(){

    //pcap_close(pcap);  
}


int CBeaconFlood::beaconFlood()
{
	
	readSsidList();
	makePacket();
	sendPacket();

    return 0;

}

void CBeaconFlood::readSsidList()
{
	std::fstream readFile;
    readFile.open(param.ssidListFile);   

    if (!readFile.is_open())
    {
		std::cout << "file can't open" <<std::endl;
		return;
	}

    while (!readFile.eof())
    {
        std::string strSsid;
        getline(readFile, strSsid);
		vecSsidList.push_back(strSsid);
        std::cout << "ssid:" <<strSsid << std::endl;    
    }
	
    readFile.close();   
    
}


void CBeaconFlood::makePacket()
{
 // 패킷 만들기 
}

void CBeaconFlood::sendPacket()
{

	// 패킷 개수 새서 보내기 

	// int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
	// if (res != 0) {
	// 	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	// }

}    