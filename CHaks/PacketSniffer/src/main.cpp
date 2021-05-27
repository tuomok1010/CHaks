#include "PacketSniffer.h"

#include <iostream>

#include <unistd.h>
#include <net/if.h>

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <protocols>\n\n"
        << "<interface name>: the interface you wish to monitor.\n"
        << "<protocols>: types of packets to monitor. Following protocols are supported:\n";

   for(std::pair<const char*, uint32_t> e : PacketSniff::supportedProtocols)
        std::cout << e.first << " ";

    std::cout << "\nExample: " << argv[0] << " eth0 " << "ARP " << "ICMPV4" << std::endl;
}

// TODO: make this more bulletproof
int ProcessArgs(int argc, char** argv, char* ifName, PacketSniff::PacketSniffer& packetSniffer)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc > N_PROTOCOLS_SUPPORTED + 2 || argc < 3)
        return APPLICATION_ERROR;

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
        return APPLICATION_ERROR;


    PacketCraft::CopyStr(ifName, IFNAMSIZ, argv[1]);

    for(int i = 2; i < argc; ++i)
    {
        PacketCraft::CopyStr(packetSniffer.protocolsSupplied[i], PROTOCOL_NAME_SIZE, argv[i]);
    }

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    PacketSniff::PacketSniffer packetSniffer;

    if(ProcessArgs(argc, argv, interfaceName, packetSniffer) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    if(packetSniffer.Init() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketSniff::PacketSniffer::Init() error!");
        return APPLICATION_ERROR;
    }

    std::cout << "protocols: ";
    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        std::cout << packetSniffer.protocolsSupplied[i] << " ";
    }

    std::cout << "\nsocket fds: ";
    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        std::cout << packetSniffer.socketFds[i] << " ";
    }
    return NO_ERROR;

    if(packetSniffer.Sniff() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketSniff::PacketSniffer::Sniff() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}