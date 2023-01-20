#include "CBeaconFlood.h"


void CParam::usage() 
{
	printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
	printf("sample : beacon-flood mon0 ssid-list.txt");
}

bool CParam::parse(int argc, char* argv[]) 
{
	if (argc != 3) {
		usage();
		return false;
	}
	dev = argv[1];
	ssidListFile = argv[2];

	return true;
}




CBeaconFlood::CBeaconFlood(CParam parameter) : param(parameter)
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
		delete[] i;
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
        std::cout << "ssid :" <<strSsid << std::endl;    
    }
	
    readFile.close();   
    
}


void CBeaconFlood::makePacket(std::string ssid)
{

	u_int8_t packetLength = 0;
	u_int8_t packetSize = sizeof(ST_WIRELESS_PACKET);
	packetSize +=sizeof(ST_TAG_DS_PARAMETER);
	packetSize +=sizeof(ST_TAG_SSID_PARAMETER);
	packetSize +=sizeof(ST_TAG_SUPPORTED_RATE);
	packetSize +=sizeof(ST_TAG_TRAFFIC_INDICATION_MAP);
	packetSize +=sizeof(ST_TAG_VENDER_SPECIFIC);
	packetSize += ssid.length();
	u_char * packet = new u_char[packetSize];
	u_char * currentPosition = packet;

	setWirelessPacket(packet);
	packetLength += sizeof(ST_WIRELESS_PACKET);
	currentPosition += packetLength;

	setTagSsid(currentPosition,ssid);
	packetLength += sizeof(ST_TAG_PARAMETER) + ssid.size(); 	
	currentPosition = packet + packetLength;

	setTagSupportedRate(currentPosition);
	packetLength += sizeof(ST_TAG_SUPPORTED_RATE);
	currentPosition = packet + packetLength;

	setTagDsParameter(currentPosition);
	packetLength += sizeof(ST_TAG_DS_PARAMETER);
	currentPosition = packet + packetLength;

	setTagTrafficIndicationMap(currentPosition);
	packetLength += sizeof(ST_TAG_TRAFFIC_INDICATION_MAP);
	currentPosition = packet + packetLength;	

	setTagVenderSpecific(currentPosition);
	packetLength += sizeof(ST_TAG_VENDER_SPECIFIC);


	vecPacketInfo.push_back(packet);		
	vecPacketLength.push_back(packetLength);


}

void CBeaconFlood::setWirelessPacket(u_char * packet)
{
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
	wirelessPacket->beaconFrame.sourceAddr =  Mac("00:11:22:33:44:55");// MAC any
	wirelessPacket->beaconFrame.bssid =  Mac("00:11:22:33:44:55"); // MAC any 
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

	
}

void CBeaconFlood::setTagSsid(u_char * packet, std::string ssid)
{
	ST_TAG_SSID_PARAMETER* tagSsidParameter = (ST_TAG_SSID_PARAMETER*)packet;
	tagSsidParameter->tagNumber = tagParameter::TAGSSIDPARAMETERSET;
	tagSsidParameter->tagLength = (u_int8_t)ssid.length();
	memcpy((void*)tagSsidParameter->ssid,ssid.data(),ssid.size());

}

void CBeaconFlood::setTagSupportedRate(u_char * packet)
{

	ST_TAG_SUPPORTED_RATE* tagSupportedRate = (ST_TAG_SUPPORTED_RATE*)packet;
	tagSupportedRate->tagNumber = tagParameter::TAGSUPPORTEDRATED;
	tagSupportedRate->tagLength= 8;
	tagSupportedRate->supportedRate[0] = 0x82;
	tagSupportedRate->supportedRate[1] = 0x84;
	tagSupportedRate->supportedRate[2] = 0x8B;
	tagSupportedRate->supportedRate[3] = 0x96;
	tagSupportedRate->supportedRate[4] = 0x24;
	tagSupportedRate->supportedRate[5] = 0x30;
	tagSupportedRate->supportedRate[6] = 0x48;
	tagSupportedRate->supportedRate[7] = 0x6c;

}

void CBeaconFlood::setTagDsParameter(u_char * packet)
{
	ST_TAG_DS_PARAMETER* tagDsParameter =  (ST_TAG_DS_PARAMETER*)packet;
	tagDsParameter->tagNumber = tagParameter::TAGDSPARAMETERSET;
	tagDsParameter->tagLength = 1;
	tagDsParameter->tagDsParameter = 1;		

}

void CBeaconFlood::setTagTrafficIndicationMap(u_char * packet)
{

	ST_TAG_TRAFFIC_INDICATION_MAP* tagTrafficIndicationMap =  (ST_TAG_TRAFFIC_INDICATION_MAP*)packet;
	tagTrafficIndicationMap->tagNumber = tagParameter::TAGTRAFFICINDICATIONMAP;
	tagTrafficIndicationMap->tagLength = 4;
	tagTrafficIndicationMap->count = 0;
	tagTrafficIndicationMap->period = 3;
	tagTrafficIndicationMap->control = 0;
	tagTrafficIndicationMap->bitmap = 0;	

}

void CBeaconFlood::setTagVenderSpecific(u_char * packet)
{

	ST_TAG_VENDER_SPECIFIC* tagVenderSpecific =  (ST_TAG_VENDER_SPECIFIC*)packet;
	tagVenderSpecific->tagNumber = tagParameter::TAGVENDORSPECIFIC;
	tagVenderSpecific->tagLength = 0x18;
	tagVenderSpecific->oui[0] = 0x00;
	tagVenderSpecific->oui[1] = 0x50;
	tagVenderSpecific->oui[2] = 0xf2;
	tagVenderSpecific->ouiType = 0x01;
	tagVenderSpecific->version = 0x0001;
	tagVenderSpecific->multiCipherSuiteOui[0] = 0x00;
	tagVenderSpecific->multiCipherSuiteOui[1] = 0x50;
	tagVenderSpecific->multiCipherSuiteOui[2] = 0xf2;
	tagVenderSpecific->multiCipherSuitetype = 0x04;
	tagVenderSpecific->unicastCipherSuiteCount = 0x0001; 
	tagVenderSpecific->unicastCipherSuiteOui1[0] = 0x00;
	tagVenderSpecific->unicastCipherSuiteOui1[1] = 0x50;
	tagVenderSpecific->unicastCipherSuiteOui1[2] = 0xf2;
	tagVenderSpecific->unicastCiphersuiteType1= 0x04;
	tagVenderSpecific->unicastCipherSuiteOui2[0] = 0x01;
	tagVenderSpecific->unicastCipherSuiteOui2[1] = 0x00;
	tagVenderSpecific->unicastCipherSuiteOui2[2] = 0x00;
	tagVenderSpecific->unicastCiphersuiteType2 = 0x50;
	tagVenderSpecific->unicastCipherSuiteOui3[0] = 0xf2;
	tagVenderSpecific->unicastCipherSuiteOui3[1] = 0x02;
	tagVenderSpecific->unicastCipherSuiteOui3[2] = 0x00;
	tagVenderSpecific->unicastCiphersuiteType3 = 0x00;	

}



void CBeaconFlood::sendPacket()
{
	for(int i = 0 ; i < vecPacketInfo.size(); i ++){
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(vecPacketInfo[i]), vecPacketLength[i]);
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}

	}
	sleep(0.0005);
}    
