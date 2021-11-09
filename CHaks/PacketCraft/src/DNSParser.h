#ifndef PC_DNS_PARSER_H
#define PC_DNS_PARSER_H

#include "PCTypes.h"
#include "PCHeaders.h"

// TODO: should we take advantage of DNSParser in NetworkUtils::ConvertDNSLayerToString()? 
// Lots of same code there as in DNSParser::Parse()

// TODO: parse questions and answers in network byte order? or add an option to do both host byte order and network byte order
// maybe add functions like "ParseToHostByteOrder() and ParseToNetworkByteOrder()"

// TODO: store qName and aName in dns label format(wwwbingcom) instead of a regular string (www.google.com), 
// also dynamically allocate memory for these names  instead of using a buffer with a prefixed length

namespace PacketCraft
{
    struct DNSQuestion
    {
        char qName[FQDN_MAX_STR_LEN];
        uint16_t qType;
        uint16_t qClass;
    };

    // IMPORTANT: remember to free() rData
    struct DNSAnswer
    {
        char aName[FQDN_MAX_STR_LEN];
        uint16_t aType;
        uint16_t aClass;
        uint32_t timeToLive;
        uint16_t rLength;
        char* rData;
    };

    class DNSParser
    {
        public:
        DNSParser();

        ~DNSParser();

        void Parse(const DNSHeader& dnsHeader);

        uint32_t nQuestions;
        uint32_t nAnswers;
        DNSQuestion* questionsArray;
        DNSAnswer* answersArray;
        const DNSHeader* header;
    };
}

#endif