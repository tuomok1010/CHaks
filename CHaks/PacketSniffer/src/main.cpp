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

    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        std::cout << PacketSniff::supportedProtocols[i] << " ";
    }

    std::cout
        << "\nExample: " << argv[0] << " eth0 " << PacketSniff::supportedProtocols[1] << " " << PacketSniff::supportedProtocols[2]
        << std::endl;
}

// TODO: make this more bulletproof
int ProcessArgs(int argc, char** argv, char* ifName, char protocols[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE])
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

    int protoIndex{0};
    for(int i = 2; i < argc; ++i)
    {
        if(PacketSniff::PacketSniffer::IsProtocolSupported(argv[i]) == TRUE)
        {
            if(PacketCraft::CompareStr(argv[i], "ALL") == TRUE)
            {
                PacketCraft::CopyStr(protocols[0], PROTOCOL_NAME_SIZE, "ALL");
                return NO_ERROR;
            }
            else
            {
                PacketCraft::CopyStr(protocols[protoIndex++], PROTOCOL_NAME_SIZE, argv[i]);
            }
        }
        else
        {
            LOG_ERROR(APPLICATION_ERROR, "unsupported protocol supplied!");
            return APPLICATION_ERROR;
        }
    }

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    char protocols[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE]{};
    int socketFds[N_PROTOCOLS_SUPPORTED]{};

    if(ProcessArgs(argc, argv, interfaceName, protocols) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }



    return NO_ERROR;
}