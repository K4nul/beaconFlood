#include "CWirelessPacket.h"


// ST_TAG_PARAMETER* ST_TAG_PARAMETER::getNextTag()
// {
//     char * currentTag = (char*)this;
//     currentTag += sizeof(ST_TAG_PARAMETER) + tagLength;
//     return (ST_TAG_PARAMETER*)currentTag; 

// }

// void* ST_TAG_PARAMETER::valuePointer(ST_TAG_PARAMETER* tagPointer)
// {
//     return tagPointer + sizeof(ST_TAG_PARAMETER);
// }

// ST_TAG_PARAMETER* ST_TAG_PARAMETER::getFirstTag(const u_char * tagPointer)
// {

//     tagPointer += sizeof(ST_IEEE80211_RADIOTAP_HEADER); 
//     tagPointer += sizeof(ST_BEACON_FRAME);
//     tagPointer += sizeof(ST_FIXED_PARAMETER);

//     return (ST_TAG_PARAMETER*)tagPointer;


// }