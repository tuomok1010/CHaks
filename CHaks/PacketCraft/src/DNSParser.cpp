#include "DNSParser.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

PacketCraft::DNSParser::DNSParser() :
    header({}),
    questionsArray(nullptr),
    answersArray(nullptr),
    parsedToNetworkFormat(FALSE)
{

}

PacketCraft::DNSParser::~DNSParser()
{
    FreeData();
}

void PacketCraft::DNSParser::FreeData()
{
    uint32_t nAnswers = parsedToNetworkFormat == FALSE ? header.ancount : ntohs(header.ancount);

    for(unsigned int i = 0; i < nAnswers; ++i)
    {
        if(answersArray[i].rLength > 0 && answersArray[i].rData != nullptr)
            free(answersArray[i].rData);
    }

    if(questionsArray != nullptr)
        free(questionsArray);

    if(answersArray != nullptr)
        free(answersArray);

    header.id = 0;
    header.rd = 0;
    header.tc = 0;
    header.aa = 0;
    header.opcode = 0;
    header.qr = 0;
    header.rcode = 0;
    header.zero = 0;
    header.ra = 0;
    header.qcount = 0;
    header.ancount = 0;
    header.nscount = 0;
    header.adcount = 0;
    parsedToNetworkFormat = FALSE;
}

void PacketCraft::DNSParser::ParseToHostFormat(const DNSHeader& dnsHeader)
{
    FreeData();
    parsedToNetworkFormat = FALSE;

    header.id = ntohs(dnsHeader.id);
    header.rd = dnsHeader.rd;
    header.tc = dnsHeader.tc;
    header.aa = dnsHeader.aa;
    header.opcode = dnsHeader.opcode;
    header.qr = dnsHeader.qr;
    header.rcode = dnsHeader.rcode;
    header.zero = dnsHeader.zero;
    header.ra = dnsHeader.ra;
    header.qcount = ntohs(dnsHeader.qcount);
    header.ancount = ntohs(dnsHeader.ancount);
    header.nscount = ntohs(dnsHeader.nscount);
    header.adcount = ntohs(dnsHeader.adcount);

    questionsArray = (DNSQuestion*)malloc(header.qcount * sizeof(DNSQuestion));
    answersArray = (DNSAnswer*)malloc(header.ancount * sizeof(DNSAnswer));

    const uint8_t* querySection = dnsHeader.querySection;

    // parse questions
    for(unsigned int i = 0; i < header.qcount; ++i)
    {
        char* qNamePtr = questionsArray[i].qName;
        uint32_t nameLength = 0; // domain name length, does not include '.' chars between labels!
        uint32_t numLabels = 0; // number of labels in domain name
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte in querySection is the length of the first label
            std::cout << "labelLength: " << labelLength << "\n";

            if(numLabels != 0 && labelLength != 0)
            {
                *qNamePtr = '.'; // each label is separated with a '.'
                ++qNamePtr; // increment pointer past the '.'
            }

            ++querySection; // increment pointer past the label length and to the start of the label in dns header.

            // if labelLength is 0, we are at the end of the name. querySection ptr now points at the qtype value
            if(labelLength == 0)
            {
                *qNamePtr = '\0';
                std::cout << "qName completely copied: " << questionsArray[i].qName << "\n";
                break;
            }
            
            memcpy(qNamePtr, querySection, labelLength); // copy new label into the qName
            querySection += labelLength; // will now point to the next label length
            qNamePtr += labelLength; // will point at the end of the currently copied name (one past final letter)
            nameLength += labelLength;
            ++numLabels;
        }
        questionsArray[i].qType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        questionsArray[i].qClass = ntohs(*(uint16_t*)querySection);
        querySection += 2; // ptr now points to the answers section
    }

    // parse answers
    for(unsigned int i = 0; i < header.ancount; ++i)
    {
        char* aNamePtr = answersArray[i].aName;
        uint32_t nameLength = 0; // domain name length, does not include '.' chars between labels!
        uint32_t numLabels = 0; // number of labels in domain name
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte in querySection is the length of the first label
            std::cout << "labelLength: " << labelLength << "\n";

            if(numLabels != 0 && labelLength != 0)
            {
                *aNamePtr = '.'; // each label is separated with a '.'
                ++aNamePtr; // increment pointer past the '.'
            }

            ++querySection; // increment pointer past the label length and to the start of the label in dns header.

            // if labelLength is 0, we are at the end of the name. querySection ptr now points at the qtype value
            if(labelLength == 0)
            {
                *aNamePtr = '\0';
                std::cout << "qName completely copied: " << questionsArray[i].qName << "\n";
                break;
            }
            
            memcpy(aNamePtr, querySection, labelLength); // copy new label into the qName
            querySection += labelLength; // will now point to the next label length
            aNamePtr += labelLength; // will point at the end of the currently copied name (one past final letter)
            nameLength += labelLength;
            ++numLabels;
        }
        answersArray[i].aType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        answersArray[i].aClass = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        answersArray[i].timeToLive = ntohl(*(uint32_t*)querySection);
        querySection += 4;
        answersArray[i].rLength = ntohs(*(uint16_t*)querySection);
        querySection += 2;

        answersArray[i].rData = (char*)malloc(answersArray[i].rLength + 1);
        memcpy(answersArray[i].rData , querySection, answersArray[i].rLength);
        memset(answersArray[i].rData + answersArray[i].rLength, '\0', 1);
        querySection += answersArray[i].rLength;
    }
}

// TODO: test
void PacketCraft::DNSParser::ParseToNetworkFormat(const DNSHeader& dnsHeader)
{
    FreeData();
    parsedToNetworkFormat = TRUE;

    header.id = dnsHeader.id;
    header.rd = dnsHeader.rd;
    header.tc = dnsHeader.tc;
    header.aa = dnsHeader.aa;
    header.opcode = dnsHeader.opcode;
    header.qr = dnsHeader.qr;
    header.rcode = dnsHeader.rcode;
    header.zero = dnsHeader.zero;
    header.ra = dnsHeader.ra;
    header.qcount = dnsHeader.qcount;
    header.ancount = dnsHeader.ancount;
    header.nscount = dnsHeader.nscount;
    header.adcount = dnsHeader.adcount;

    questionsArray = (DNSQuestion*)malloc(ntohs(header.qcount) * sizeof(DNSQuestion));
    answersArray = (DNSAnswer*)malloc(ntohs(header.ancount) * sizeof(DNSAnswer));

    const uint8_t* querySection = dnsHeader.querySection;

    // parse questions
    for(unsigned int i = 0; i < ntohs(header.qcount); ++i)
    {
        char* qNamePtr = questionsArray[i].qName;
        uint32_t nameLength = 0; // domain name length, does not include '.' chars between labels!
        uint32_t numLabels = 0; // number of labels in domain name
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte in querySection is the length of the first label
            std::cout << "labelLength: " << labelLength << "\n";

            *qNamePtr = labelLength;
            ++qNamePtr;
            ++querySection; // increment pointer past the label length and to the start of the label in dns header.

            // if labelLength is 0, we are at the end of the name. querySection ptr now points at the qtype value
            if(labelLength == 0)
            {
                ++qNamePtr;
                *qNamePtr = '\0';
                std::cout << "qName completely copied: " << questionsArray[i].qName << "\n";
                break;
            }
            
            memcpy(qNamePtr, querySection, labelLength); // copy new label into the qName
            querySection += labelLength; // will now point to the next label length
            qNamePtr += labelLength; // will point at the end of the currently copied name (one past final letter)
            nameLength += labelLength;
            ++numLabels;
        }
        questionsArray[i].qType = *(uint16_t*)querySection;
        querySection += 2;
        questionsArray[i].qClass = *(uint16_t*)querySection;
        querySection += 2; // ptr now points to the answers section
    }

    // parse answers
    for(unsigned int i = 0; i < ntohs(header.ancount); ++i)
    {
        char* aNamePtr = answersArray[i].aName;
        uint32_t nameLength = 0; // domain name length, does not include '.' chars between labels!
        uint32_t numLabels = 0; // number of labels in domain name
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte in querySection is the length of the first label
            std::cout << "labelLength: " << labelLength << "\n";

            *aNamePtr = labelLength;
            ++aNamePtr;
            ++querySection; // increment pointer past the label length and to the start of the label in dns header.

            // if labelLength is 0, we are at the end of the name. querySection ptr now points at the qtype value
            if(labelLength == 0)
            {
                ++aNamePtr;
                *aNamePtr = '\0';
                std::cout << "qName completely copied: " << questionsArray[i].qName << "\n";
                break;
            }
            
            memcpy(aNamePtr, querySection, labelLength); // copy new label into the qName
            querySection += labelLength; // will now point to the next label length
            aNamePtr += labelLength; // will point at the end of the currently copied name (one past final letter)
            nameLength += labelLength;
            ++numLabels;
        }
        answersArray[i].aType = *(uint16_t*)querySection;
        querySection += 2;
        answersArray[i].aClass = *(uint16_t*)querySection;
        querySection += 2;
        answersArray[i].timeToLive = *(uint32_t*)querySection;
        querySection += 4;
        answersArray[i].rLength = *(uint16_t*)querySection;
        querySection += 2;

        answersArray[i].rData = (char*)malloc(answersArray[i].rLength + 1);
        memcpy(answersArray[i].rData , querySection, answersArray[i].rLength);
        memset(answersArray[i].rData + answersArray[i].rLength, '\0', 1);
        querySection += answersArray[i].rLength;
    }
}

void PacketCraft::DNSParser::PrintQueries()
{
    uint32_t nQuestions = parsedToNetworkFormat == FALSE ? header.qcount : ntohs(header.qcount);
    uint32_t nAnswers = parsedToNetworkFormat == FALSE ? header.ancount : ntohs(header.ancount);

    for(unsigned int i = 0; i < nQuestions; ++i)
    {
        std::cout 
            << "qName: " << questionsArray[i].qName << "\n" 
            << "qType: " << ((parsedToNetworkFormat == FALSE) ? questionsArray[i].qType : ntohs(questionsArray[i].qType)) << "\n"
            << "qClass: " << ((parsedToNetworkFormat == FALSE) ? questionsArray[i].qClass : ntohs(questionsArray[i].qClass)) << "\n";
    }

    for(unsigned int i = 0; i < nAnswers; ++i)
    {
        std::cout
            << "aName: " << answersArray[i].aName << "\n"
            << "aType: " << ((parsedToNetworkFormat == FALSE) ? answersArray[i].aType : ntohs(answersArray[i].aType)) << "\n"
            << "aClass: " << ((parsedToNetworkFormat == FALSE) ? answersArray[i].aClass : ntohs(answersArray[i].aClass)) << "\n"
            << "TTL: " << ((parsedToNetworkFormat == FALSE) ? answersArray[i].timeToLive : ntohl(answersArray[i].timeToLive)) << "\n"
            << "rLength: " << ((parsedToNetworkFormat == FALSE) ? answersArray[i].rLength : ntohs(answersArray[i].rLength)) << "\n"
            << "rData: ";

            for(unsigned int j = 0; j < ((parsedToNetworkFormat == FALSE) ? answersArray[i].rLength : ntohs(answersArray[i].rLength)); ++j)
            {
                std::cout << answersArray[i].rData[j];
            }

            std::cout << "\n";
    }

    std::cout << std::flush;
}