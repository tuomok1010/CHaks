#include "FileInterceptor.h"

#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <poll.h>
#include <arpa/inet.h>

CHaks::FileInterceptor::FileInterceptor()
{

}

CHaks::FileInterceptor::~FileInterceptor()
{
    
}

int CHaks::FileInterceptor::Run(int socketFd, char* interfaceName, uint32_t ipVersion, char* targetIP, char* downloadLink)
{
    pollfd pollFds[3]{};
        
    // we want to monitor console input, entering something there stops the program
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;

    pollFds[1].fd = socketFd;
    pollFds[1].events = POLLIN;

    PacketCraft::Packet packet;

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
                if(FilterPackets(socketFd, ipVersion, targetIP, downloadLink, packet) == APPLICATION_ERROR)
                {
                    LOG_ERROR(APPLICATION_ERROR, "FilterPackets error");
                    return APPLICATION_ERROR;
                }
            }
        }
    }
}

int CHaks::FileInterceptor::FilterPackets(int socketFd, uint32_t ipVersion, char* targetIP, char* downloadLink, PacketCraft::Packet& packet)
{
    if(packet.Receive(socketFd, 0) == APPLICATION_ERROR)
    {
        // LOG_ERROR(APPLICATION_WARNING, "PacketCraft::Packet::Receive() error");
        return APPLICATION_WARNING;
    }

    sockaddr_in targetIPAddr{};
    if(inet_pton(AF_INET, targetIP, &targetIPAddr.sin_addr) == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "inet_pton() error");
        return APPLICATION_ERROR;
    }

    char* httpResponse = (char*)packet.FindLayerByType(PC_HTTP_RESPONSE);
    char* httpRequest = (char*)packet.FindLayerByType(PC_HTTP_REQUEST);

    char packetFileName[255]{};
    char packetDomainName[255]{};
    char packetDownloadLink[1024]{};

    if(httpRequest != nullptr)
    {
        /*
        if(PacketCraft::GetHTTPMethod((uint8_t*)httpRequest) == PC_HTTP_GET)
        {
            std::cout << httpRequest << std::endl;
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
            std::cout << "full packet download link: " << packetDownloadLink << std::endl;

            if(PacketCraft::CompareStr(packetDownloadLink, downloadLink) == TRUE)
            {
                std::cout << "packet containing " << packetDownloadLink << " matches " << downloadLink << std::endl;
            }
        }
        */
    }
    else if(httpResponse != nullptr)
    {
        std::cout << httpResponse << std::endl;
        
        if(ipVersion == AF_INET)
        {
            IPv4Header* ipv4Header = (IPv4Header*)packet.FindLayerByType(PC_IPV4);
            if(targetIPAddr.sin_addr.s_addr == ipv4Header->ip_dst.s_addr)
            {

            }
        }
    }
}