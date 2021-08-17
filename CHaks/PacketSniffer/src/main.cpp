#include "PacketSniffer.h"

#include <iostream>

#include <unistd.h>
#include <net/if.h>

void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <save to file> <protocols>\n\n"
        << "<interface name>: the interface you wish to monitor.\n"
        << "<save to file(true/false)>: if true saves packet data to file, if false prints packets in console"
        << "<protocols>: types of packets to monitor. Following protocols are supported:\n";

   for(std::pair<const char*, uint32_t> e : CHaks::supportedProtocols)
        std::cout << e.first << " ";

    std::cout << "\nExample: " << argv[0] << " eth0 " << "1" << "ARP " << "ICMPV4" << std::endl;
}

// TODO: make this more bulletproof
int ProcessArgs(int argc, char** argv, char* ifName, CHaks::PacketSniffer& packetSniffer)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc > N_PROTOCOLS_SUPPORTED + 3 || argc < 4)
        return APPLICATION_ERROR;

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
        return APPLICATION_ERROR;


    PacketCraft::CopyStr(ifName, IFNAMSIZ, argv[1]);

    if((argv[2][0] == '1' || argv[2][0] == 't' || argv[2][0] == 'T' || argv[2][0] == 'y' || argv[2][0] == 'Y') || 
        (PacketCraft::CompareStr(argv[2], "true") == TRUE) || PacketCraft::CompareStr(argv[2], "TRUE") == TRUE)
    {
        packetSniffer.saveToFile = TRUE;
    }
    else
    {
        packetSniffer.saveToFile = FALSE;
    }

    for(int i = 3, j = 0; i < argc; ++i, ++j)
    {
        PacketCraft::CopyStr(packetSniffer.protocolsSupplied[j], PROTOCOL_NAME_SIZE, argv[i]);
    }

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    CHaks::PacketSniffer packetSniffer;

/*
    const char* str1 = "this is a test HTTP/1.1 thing";
    const char* pattern  = "HTTP";

    int resultIndex = PacketCraft::FindInStr(str1, pattern);
    if(resultIndex > -1)
    {
        std::cout << "pattern found at " << resultIndex << std::endl;
    }
    else
    {
        std::cout << "pattern not found" << std::endl;
    }

    return 0;
*/

    if(ProcessArgs(argc, argv, interfaceName, packetSniffer) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    if(packetSniffer.Init(interfaceName) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::PacketSniffer::Init() error!");
        return APPLICATION_ERROR;
    }

    if(packetSniffer.Sniff() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::PacketSniffer::Sniff() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}