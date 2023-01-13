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
	u_char * packet;
	ST_WIRELESS_PACKET * wirelessPacket = (ST_WIRELESS_PACKET*)packet;
	

	wirelessPacket->radioTapHeader.version = 0;
	wirelessPacket->radioTapHeader.pad = 0;
	wirelessPacket->radioTapHeader.len = 24;
	wirelessPacket->radioTapHeader.present[0] = 0x2e; //고치기
	wirelessPacket->radioTapHeader.present[1] = 0x40;
	wirelessPacket->radioTapHeader.present[2] = 0x00;
	wirelessPacket->radioTapHeader.present[3] = 0xa0;
	wirelessPacket->radioTapHeader.present[4] = 0x20;
	wirelessPacket->radioTapHeader.present[5] = 0x08;
	wirelessPacket->radioTapHeader.present[6] = 0x00;
	wirelessPacket->radioTapHeader.present[7] = 0x00;
	wirelessPacket->radioTapHeader.flags = 00;
	wirelessPacket->radioTapHeader.dataRate = 02;
	wirelessPacket->radioTapHeader.channelFrequency = 2412;
	wirelessPacket->radioTapHeader.channelFlags = 160;
	wirelessPacket->radioTapHeader.antennaSignal = -63;
	wirelessPacket->radioTapHeader.antenna = 00;
	wirelessPacket->radioTapHeader.rxFlags = 0000;
	wirelessPacket->radioTapHeader.antennaSignalT = -63; 
	wirelessPacket->radioTapHeader.antennaT =  00;
	wirelessPacket->beaconFrame.frameControl = 80;
	wirelessPacket->beaconFrame.duration = 0000;
	wirelessPacket->beaconFrame.destinationAddr =  Mac("FF:FF:FF:FF:FF:FF");// MAC BD
	wirelessPacket->beaconFrame.sourceAddr =  Mac("11:22:33:44:55:66");// MAC any
	wirelessPacket->beaconFrame.bssid =  Mac("11:22:33:44:55:66"); // MAC any 
	wirelessPacket->beaconFrame.seqFragNum = 0000; 
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
	printf("%d\n",packetLength);
	u_char * fPointer = packet;
	ST_TAG_PARAMETER* tag = ST_TAG_PARAMETER::getFirstTag(packet);
	tag->tagNumber = tagParameter::TAGSSIDPARAMETERSET;
	tag->tagLength = ssid.length();
	memcpy(tag->valuePointer(tag),ssid.data(),ssid.size());

	packetLength += tag->tagLength + sizeof(ST_TAG_PARAMETER);
	printf("%d\n",packetLength);

	tag = tag->getNextTag();

	tag->tagNumber = tagParameter::TAGSUPPORTEDRATED;
	tag->tagLength = 8;
	char supportedRate[8];
	supportedRate[0] = 0x82;	
	supportedRate[1] = 0x84;
	supportedRate[2] = 0x88;
	supportedRate[3] = 0x96;
	supportedRate[4] = 0x24;
	supportedRate[5] = 0x30;
	supportedRate[6] = 0x48;
	supportedRate[7] = 0x6C;

	packetLength += tag->tagLength + sizeof(ST_TAG_PARAMETER);
	memcpy(tag->valuePointer(tag),supportedRate,tag->tagLength);

	printf("%d\n",packetLength);

	tag = tag->getNextTag();

	tag->tagNumber = tagParameter::TAGDSPARAMETERSET;
	tag->tagLength = 1;
	u_int8_t tagDsParameter = 1;

	packetLength += tag->tagLength + sizeof(ST_TAG_PARAMETER);	
	memcpy(tag->valuePointer(tag),(char*)&tagDsParameter,tag->tagLength);
	printf("%d\n",packetLength);

	// tag = tag->getNextTag();
	vecPacketLength.push_back(packetLength);
	vecPacketInfo.push_back(fPointer);

	// tag->tagNumber = tagParameter::TAGTRAFFICINDICATIONMAP;
	// tag->tagLength = 4;
	// pointer = (u_char*)tag->valuePointer();
	// *pointer++ = 0;
	// *pointer++ = 3;
	// *pointer++ = 0;
	// *pointer = 0;
	// tag - tag->getNextTag();

	// char vendor[] = "\xdd\x18\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x02\x00\x00";
	// memcpy(tag, vendor, sizeof(vendor) -1);

}

void CBeaconFlood::sendPacket()
{

	for(int i = 0 ; i < vecPacketInfo.size(); i ++){
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&vecPacketInfo[i]), vecPacketLength[i]+10);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}

	}


}    