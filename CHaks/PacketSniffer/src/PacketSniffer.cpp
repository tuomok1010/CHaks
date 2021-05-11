#include "PacketSniffer.h"

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
    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        close(socketFds[i]);
    }
}

int PacketSniff::PacketSniffer::Init(char protocols[N_PROTOCOLS_SUPPORTED][PROTOCOL_NAME_SIZE])
{
    bool32 enableAllProtocols = PacketCraft::CompareStr(protocols[0], "ALL");
    int socketIndex{0};

    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        if(PacketCraft::CompareStr(protocols[i], "ARP") == TRUE || enableAllProtocols == TRUE)
        {
            if((socketFds[socketIndex++] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP)) == -1))
            {
                LOG_ERROR(APPLICATION_ERROR, "socket() error!");
                return APPLICATION_ERROR;
            }
        }

        if(PacketCraft::CompareStr(protocols[i], "IPV4") == TRUE || enableAllProtocols == TRUE)
        {
            if((socketFds[socketIndex] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)) == -1))
            {
                LOG_ERROR(APPLICATION_ERROR, "socket() error!");
                return APPLICATION_ERROR;
            }
        }

        if(PacketCraft::CompareStr(protocols[i], "ICMPV4") == TRUE || enableAllProtocols == TRUE)
        {
            if((socketFds[socketIndex] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)) == -1))
            {
                LOG_ERROR(APPLICATION_ERROR, "socket() error!");
                return APPLICATION_ERROR;
            }
        }
    }

    nSocketsUsed = socketIndex + 1;
    return NO_ERROR;
}

int PacketSniff::PacketSniffer::ReceivePackets()
{
    pollfd* pollFds = new pollfd[nSocketsUsed];

    for(int i = 0; i < nSocketsUsed; ++i)
    {
        pollFds[i].fd = socketFds[i];
        pollFds[i].events = POLLIN;
    }

    while(true)
    {
        int nEvents = poll(pollFds, nSocketsUsed, -1);

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
            for(int i = 0; i < nSocketsUsed; ++i)
            {
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
}

bool32 PacketSniff::PacketSniffer::IsProtocolSupported(const char* protocol)
{
    if(PacketCraft::CompareStr(protocol, "ALL") == TRUE)
        return TRUE;

    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        if(PacketCraft::CompareStr(protocol, supportedProtocols[i]) == TRUE)
            return TRUE;
    }

    return FALSE;
}

int PacketSniff::PacketSniffer::ReceivePacket(const int socketFd)
{
    return NO_ERROR;
}