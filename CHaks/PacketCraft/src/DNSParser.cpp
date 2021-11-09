#include "DNSParser.h"

#include <cstdlib>
#include <cstring>

PacketCraft::DNSParser::DNSParser()
{

}

PacketCraft::DNSParser::~DNSParser()
{
    for(unsigned int i = 0; i < nAnswers; ++i)
        free(answersArray[i].rData);

    free(questionsArray);
    free(answersArray);
}

void PacketCraft::DNSParser::Parse(const DNSHeader& dnsHeader)
{
    nQuestions = ntohs(dnsHeader.qcount);
    nAnswers = ntohs(dnsHeader.ancount);
    questionsArray = (DNSQuestion*)malloc(nQuestions * sizeof(DNSQuestion));
    answersArray = (DNSAnswer*)malloc(nAnswers * sizeof(DNSAnswer));
    header = &dnsHeader;

    const uint8_t* querySection = header->querySection;

    // parse questions
    for(unsigned int i = 0; i < nQuestions; ++i)
    {
        char* qNamePtr = questionsArray[i].qName;
        uint32_t nameLength = 0;
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte is the length of the first label
            ++querySection; // increment pointer to the start of the qname.
            memcpy(qNamePtr, querySection, labelLength); // copy label into the qName buffer
            querySection += labelLength; // will now point to the next label
            qNamePtr += labelLength;

            // append a '.' after each label
            *qNamePtr = '.';
            ++qNamePtr;

            nameLength += labelLength;

            // if length of next label is 0, we have reached the end of the qname string. We increment the pointer to point to the QTYPE value.
            if((uint32_t)*querySection == 0)
            {
                --qNamePtr; // move pointer back because we want the last '.' character to be replaced with a '\0'
                ++querySection;
                break;
            }
        }
        *qNamePtr = '\0';
        questionsArray[i].qType = ntohs(*(uint16_t*)querySection);
        querySection += 2;
        questionsArray[i].qClass = ntohs(*(uint16_t*)querySection);
        querySection += 2; // ptr now points to the answers section
    }

    // parse answers
    for(unsigned int i = 0; i < nAnswers; ++i)
    {
        char* aNamePtr = answersArray[i].aName;
        uint32_t nameLength = 0;
        while(true) // fills the qName buffer with a domain name
        {
            uint32_t labelLength = (uint32_t)*querySection; // first byte is the length of the first label
            ++querySection; // increment pointer to the start of the qname.
            memcpy(aNamePtr, querySection, labelLength); // copy label into the qName buffer
            querySection += labelLength; // will now point to the next label
            aNamePtr += labelLength;

            // append a '.' after each label
            *aNamePtr = '.';
            ++aNamePtr;

            nameLength += labelLength;

            // if length of next label is 0, we have reached the end of the qname string. We increment the pointer to point to the QTYPE value.
            if((uint32_t)*querySection == 0)
            {
                --aNamePtr; // move pointer back because we want the last '.' character to be replaced with a '\0'
                ++querySection;
                break;
            }
        }
        *aNamePtr = '\0';
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