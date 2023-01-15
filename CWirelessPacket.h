#include "CMac.h"
#include <iostream>


enum tagParameter {
	TAGSSIDPARAMETERSET = 0,
	TAGSUPPORTEDRATED = 1,
	TAGDSPARAMETERSET = 3,
	TAGTRAFFICINDICATIONMAP = 5,
	TAGCOUNTRYINFORMATION = 7,
	TAGQBSSLOADELE0x0104MENT = 11,
	TAGHTCAPABILITIES = 45,
	TAGRSNINFORMATION = 48,
	TAGHTINFORMATION = 61,
	TAGVENDORSPECIFIC = 221
};


struct ST_FIXED_PARAMETER
{
	u_int8_t timestamp[8];
	u_int16_t beaconInterval;
	u_int16_t capabilityInfo;
};

struct ST_BEACON_FRAME
{
	u_int16_t frameControl; 
	u_int16_t duration;
	Mac destinationAddr;
	Mac sourceAddr;
	Mac bssid;
	u_int16_t seqFragNum;

};

struct ST_IEEE80211_RADIOTAP_HEADER 
{
    u_int8_t        version;     
    u_int8_t        pad;
    u_int16_t       len;         
    u_int8_t		present[8];  
	u_int8_t		flags;
	u_int8_t		dataRate;
	u_int16_t		channelFrequency;
	u_int16_t		channelFlags;  
	int8_t			antennaSignal; 
	u_int8_t		antenna;
	u_int16_t		rxFlags; 
	int8_t			antennaSignalT;
	u_int8_t		antennaT;

};

struct ST_WIRELESS_PACKET 
{
	ST_IEEE80211_RADIOTAP_HEADER radioTapHeader;
	ST_BEACON_FRAME beaconFrame;
	ST_FIXED_PARAMETER fixedParameter;

};

struct ST_TAG_PARAMETER
{
	u_int8_t tagNumber;
	u_int8_t tagLength;
	
};

struct ST_TAG_DS_PARAMETER : ST_TAG_PARAMETER
{
	u_int8_t tagDsParameter;

};

struct ST_TAG_SUPPORTED_RATE : ST_TAG_PARAMETER
{	
	u_int8_t supportedRate[8];

};


struct ST_TAG_TRAFFIC_INDICATION_MAP : ST_TAG_PARAMETER
{	

	u_int8_t count;
	u_int8_t period;
	u_int8_t control;
	u_int8_t bitmap;

};


struct ST_TAG_VENDER_SPECIFIC : ST_TAG_PARAMETER  
{	
	
	u_int8_t oui[3];
	u_int8_t ouiType;
	u_int16_t version;
	u_int8_t multiCipherSuiteOui[3];
	u_int8_t multiCipherSuitetype;
	u_int16_t unicastCipherSuiteCount;
	u_int8_t unicastCipherSuiteOui1[3];
	u_int8_t unicastCiphersuiteType1;
	u_int8_t unicastCipherSuiteOui2[3];
	u_int8_t unicastCiphersuiteType2;
	u_int8_t unicastCipherSuiteOui3[3];
	u_int8_t unicastCiphersuiteType3;


};



struct ST_TAG_SSID_PARAMETER : ST_TAG_PARAMETER
{	
	char ssid[];

};






