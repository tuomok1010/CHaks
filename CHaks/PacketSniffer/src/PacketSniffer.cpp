#include "PacketSniffer.h"

#include <iostream>
#include <unistd.h>
#include <poll.h>
#include <netinet/in.h>

PacketSniff::PacketSniffer::PacketSniffer()
{
    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        socketFds[i] = -1;
    }
}

PacketSniff::PacketSniffer::~PacketSniffer()
{
    CloseSockets();
}

int PacketSniff::PacketSniffer::Init()
{
    int socketIndex{0};
    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        if(PacketCraft::CompareStr(protocolsSupplied[i], ""))
            break;

        if(PacketSniff::PacketSniffer::IsProtocolSupported(protocolsSupplied[i]) == TRUE)
        {
            // NOTE: "ALL" and "ETHERNET" are basically the same since the program only supports ethernet frames
            if(PacketCraft::CompareStr(protocolsSupplied[i], "ALL") == TRUE)
            {
                CloseSockets();
                if((socketFds[0] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) == -1))
                {
                    LOG_ERROR(APPLICATION_ERROR, "socket() error!");
                    return APPLICATION_ERROR;
                }
                nSocketsUsed = 1;
                return NO_ERROR;
            }

            if(PacketCraft::CompareStr(protocolsSupplied[i], "ETHERNET") == TRUE)
            {
                CloseSockets();
                if((socketFds[0] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) == -1))
                {
                    LOG_ERROR(APPLICATION_ERROR, "socket() error!");
                    return APPLICATION_ERROR;
                }
                nSocketsUsed = 1;
                return NO_ERROR;
            }

            if(PacketCraft::CompareStr(protocolsSupplied[i], "ARP") == TRUE)
            {
                if((socketFds[socketIndex++] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP)) == -1))
                {
                    LOG_ERROR(APPLICATION_ERROR, "socket() error!");
                    return APPLICATION_ERROR;
                }
            }

            if(PacketCraft::CompareStr(protocolsSupplied[i], "IPV4") == TRUE)
            {
                if((socketFds[socketIndex++] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)) == -1))
                {
                    LOG_ERROR(APPLICATION_ERROR, "socket() error!");
                    return APPLICATION_ERROR;
                }
            }

            if(PacketCraft::CompareStr(protocolsSupplied[i], "ICMPV4") == TRUE)
            {
                if((socketFds[socketIndex++] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)) == -1))
                {
                    LOG_ERROR(APPLICATION_ERROR, "socket() error!");
                    return APPLICATION_ERROR;
                }
            }
        }
        else
        {
            LOG_ERROR(APPLICATION_ERROR, "unsupported protocol supplied!");
            return APPLICATION_ERROR;
        }
    }

    nSocketsUsed = socketIndex + 1;
    return NO_ERROR;
}

int PacketSniff::PacketSniffer::Sniff()
{
    pollfd* pollFds = new pollfd[nSocketsUsed + 1];

    // we want to monitor console input, entering something there stops the sniffer
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;

    for(int i = 0; i < nSocketsUsed; ++i)
    {
        pollFds[i + 1].fd = socketFds[i];
        pollFds[i + 1].events = POLLIN;
    }

    std::cout << "sniffing... press enter to stop\n" << std::endl;
    // sleeping for 2 seconds to make sure user sees the message above
    sleep(2);

    while(true)
    {
        int nEvents = poll(pollFds, nSocketsUsed + 1, -1);

        if(nEvents == -1)
        {
            delete pollFds;
            LOG_ERROR(APPLICATION_ERROR, "poll() error!");
            return APPLICATION_ERROR;
        }
        else if(nEvents == 0)
        {
            delete pollFds;
            LOG_ERROR(APPLICATION_ERROR, "poll() timeout!");
            return APPLICATION_ERROR;
        }
        else
        {
            for(int i = 0; i < nSocketsUsed; ++i)
            {
                if((i == 0) && (pollFds[i].revents & POLLIN))
                {
                    std::cout << "quitting...\n";
                    delete pollFds;
                    return NO_ERROR;
                }

                if(pollFds[i].revents & POLLIN)
                {
                    if(ReceivePacket(pollFds[i].fd) == APPLICATION_ERROR)
                    {
                        LOG_ERROR(APPLICATION_ERROR, "error receiving packet!");
                        continue;
                    }
                }
            }
        }
    }

    return NO_ERROR;    
}

bool32 PacketSniff::PacketSniffer::IsProtocolSupported(const char* protocol)
{
    if(PacketCraft::CompareStr(protocol, "ALL") == TRUE)
        return TRUE;

   for(std::pair<const char*, int> e : supportedProtocols)
   {
        if(PacketCraft::CompareStr(protocol, e.first) == TRUE)
            return TRUE;
   }

    return FALSE;
}

int PacketSniff::PacketSniffer::ReceivePacket(const int socketFd)
{
    PacketCraft::Packet packet;
    if(packet.Receive(socketFd, 0, 0) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Receive() error!");
        return APPLICATION_ERROR;
    }

    bool32 isValid{FALSE};

    for(unsigned int i = 0; i < packet.GetNLayers(); ++i)
    {
        for(std::pair<const char*, uint32_t> e : supportedProtocols)
        {
            if(packet.GetLayerType(i) == e.second)
                isValid = TRUE;
        }
    }

    if(isValid == TRUE)
    {
        std::cout << "Packet received:\n";

        if(packet.Print() == APPLICATION_ERROR)
        {
            LOG_ERROR(APPLICATION_ERROR, "PrintPacket() error!");
            return APPLICATION_ERROR;
        }

        std::cout << std::endl;
    }

    return NO_ERROR;
}

void PacketSniff::PacketSniffer::CloseSockets()
{
    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        close(socketFds[i]);
        socketFds[i] = -1;
    }
}