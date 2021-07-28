#include "PacketSniffer.h"

#include <iostream>
#include <ctime>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>

#include <unistd.h>
#include <poll.h>
#include <netinet/in.h>

CHaks::PacketSniffer::PacketSniffer() :
    socketFd(-1),
    packetNumber(0)
{

}

CHaks::PacketSniffer::~PacketSniffer()
{
    CloseSocket();
}

int CHaks::PacketSniffer::Init(const char* interfaceName)
{
    CloseSocket();

    if(((socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1))
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }

    if(setsockopt(socketFd, SOL_SOCKET, SO_BINDTODEVICE, interfaceName, PacketCraft::GetStrLen(interfaceName)) == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "setsockopt() error!");
        return APPLICATION_ERROR;
    }

    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {
        if(PacketCraft::CompareStr(protocolsSupplied[i], "") == TRUE)
            continue;

        // std::cout << "verifying following protocol: " << protocolsSupplied[i] << "\n";

        if(IsProtocolSupported(protocolsSupplied[i]) == FALSE)
        {
            LOG_ERROR(APPLICATION_ERROR, "unsupported protocol supplied!");
            return APPLICATION_ERROR;
        }
    }

    if(saveToFile == TRUE)
    {
        // current date/time based on current system
        time_t now = time(0);
        // convert now to string form
        char* dt = ctime(&now);

        char path[PATH_MAX_SIZE]{"../../saves/"};
        memcpy(path + PacketCraft::GetStrLen(path), dt, PacketCraft::GetStrLen(dt) - 1);

        if(mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO) == -1)
        {
            LOG_ERROR(APPLICATION_ERROR, "mkdir() error!");
            return APPLICATION_ERROR;
        }

        memcpy(path + PacketCraft::GetStrLen(path), "/", 1);
        memcpy(savePath, path, PacketCraft::GetStrLen(path) + 1);
    }

    return NO_ERROR;
}

int CHaks::PacketSniffer::Sniff()
{
    pollfd pollFds[2]{};

    // we want to monitor console input, entering something there stops the sniffer
    pollFds[0].fd = 0;
    pollFds[0].events = POLLIN;

    pollFds[1].fd = socketFd;
    pollFds[1].events = POLLIN;

    std::cout << "sniffing... press enter to stop\n" << std::endl;

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
            for(unsigned int i = 0; i < sizeof(pollFds) / sizeof(pollFds[0]); ++i)
            {
                if((i == 0) && (pollFds[i].revents & POLLIN))
                {
                    std::cout << "quitting...\n";
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

bool32 CHaks::PacketSniffer::IsProtocolSupported(const char* protocol) const
{
    for(const std::pair<const char*, uint32_t>& e : supportedProtocols)
    {
        if(PacketCraft::CompareStr(protocol, e.first) == TRUE)
            return TRUE;
    }

    return FALSE;
}

bool32 CHaks::PacketSniffer::IsProtocolSupported(uint32_t protocol) const
{
    for(const std::pair<const char*, uint32_t>& e : supportedProtocols)
    {
        if(protocol == e.second)
            return TRUE;
    }

    return FALSE;
}

int CHaks::PacketSniffer::ReceivePacket(const int socketFd)
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
        for(unsigned int j = 0; j < N_PROTOCOLS_SUPPORTED; ++j)
        {
            if(PacketCraft::CompareStr(protocolsSupplied[j], "") == TRUE)
                break;
            
            const char* packetProtocolStr = PacketCraft::ProtoUint32ToStr(packet.GetLayerType(i));
            if(PacketCraft::CompareStr(packetProtocolStr, protocolsSupplied[j]) == TRUE)
            {
                isValid = TRUE;
            }
        }
    }

    if(isValid == TRUE)
    {
        if(saveToFile == TRUE)
        {
            std::cout << "Packet saved to file\n";
            if(SavePacketToFile(packet) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "SavePacketToFile() error!");
                return APPLICATION_ERROR;
            }
        }
        else
        {
            std::cout << "Packet received:\n";
            if(packet.Print() == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "PrintPacket() error!");
                return APPLICATION_ERROR;
            }

            std::cout << std::endl;
        }

        ++packetNumber;
    }

    return NO_ERROR;
}

void CHaks::PacketSniffer::CloseSocket()
{
    close(socketFd);
    socketFd = -1;
}

int CHaks::PacketSniffer::SavePacketToFile(const PacketCraft::Packet& packet)
{
    char fileName[100]{};
    const char* packetNumStr = std::to_string(packetNumber).c_str();
    PacketCraft::CopyStr(fileName, sizeof(fileName), packetNumStr);

    PacketCraft::CopyStr(fileName + PacketCraft::GetStrLen(packetNumStr), 1, "_");
    char* fileNamePtr = fileName + PacketCraft::GetStrLen(packetNumStr) + 1;

    for(unsigned int i = 0; i < packet.GetNLayers(); ++i)
    {
        const char* proto = PacketCraft::ProtoUint32ToStr(packet.GetLayerType(i));
        PacketCraft::CopyStr(fileNamePtr, PROTOCOL_NAME_SIZE, proto);
        fileNamePtr += PacketCraft::GetStrLen(proto);
        PacketCraft::CopyStr(fileNamePtr, 1, "_");
        ++fileNamePtr;
    }

    PacketCraft::CopyStr(fileNamePtr, 5, ".txt");
    std::cout << "file name is " << fileName << std::endl;

    char fullPath[PATH_MAX_SIZE]{};
    memcpy(fullPath, savePath, PacketCraft::GetStrLen(savePath));
    memcpy(fullPath + PacketCraft::GetStrLen(savePath), fileName, PacketCraft::GetStrLen(fileName) + 1);

    std::ofstream file;
    file.open(fullPath, std::ofstream::out | std::ofstream::app);

    uint32_t bufferSize = 5000;
    char* buffer = (char*)malloc(bufferSize);
    uint32_t layerSize = 0; // next layer size, used to calculate data/options size of payloads
    for(unsigned int i = 0; i < packet.GetNLayers(); ++i)
    {
        uint32_t layerProtocol = packet.GetLayerType(i);
        switch(layerProtocol)
        {
            case PC_ETHER_II:
            {
                EthHeader* ethHeader = (EthHeader*)packet.GetLayerStart(i);
                PacketCraft::ConvertEthLayerToString(buffer, bufferSize, ethHeader);
                file.write(buffer, PacketCraft::GetStrLen(buffer));
                break;
            }
            case PC_ARP:
            {
                ARPHeader* arpHeader = (ARPHeader*)packet.GetLayerStart(i);
                PacketCraft::ConvertARPLayerToString(buffer, bufferSize, arpHeader);
                file.write(buffer, PacketCraft::GetStrLen(buffer));
                break;
            }
            case PC_IPV4:
            {
                IPv4Header* ipv4Header = (IPv4Header*)packet.GetLayerStart(i);
                PacketCraft::ConvertIPv4LayerToString(buffer, bufferSize, ipv4Header);

                layerSize = ntohs(ipv4Header->ip_len) - (ipv4Header->ip_hl * 32 / 8);

                file.write(buffer, PacketCraft::GetStrLen(buffer));
                break;
            }
            case PC_IPV6:
            {
                IPv6Header* ipv6Header = (IPv6Header*)packet.GetLayerStart(i);
                PacketCraft::ConvertIPv6LayerToString(buffer, bufferSize, ipv6Header);
                uint32_t nextProtocol = ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

                if(nextProtocol == IPPROTO_ICMPV6)
                    layerSize = ntohs(ipv6Header->ip6_ctlun.ip6_un1.ip6_un1_plen);

                file.write(buffer, PacketCraft::GetStrLen(buffer));
                break;
            }
            case PC_ICMPV4:
            {
                ICMPv4Header* icmpv4Header = (ICMPv4Header*)packet.GetLayerStart(i);
                PacketCraft::ConvertICMPv4LayerToString(buffer, bufferSize, icmpv4Header, layerSize - sizeof(ICMPv4Header));
                file.write(buffer, PacketCraft::GetStrLen(buffer));
                break;
            }
            case PC_ICMPV6:
            {
                ICMPv6Header* icmpv6Header = (ICMPv6Header*)packet.GetLayerStart(i);
                PacketCraft::ConvertICMPv6LayerToString(buffer, bufferSize, icmpv6Header, layerSize - sizeof(ICMPv6Header));
                file.write(buffer, PacketCraft::GetStrLen(buffer));
                break;
            }
            case PC_TCP:
            {
                TCPHeader* tcpHeader = (TCPHeader*)packet.GetLayerStart(i);

                if(tcpHeader->doff > 5)
                    PacketCraft::ConvertTCPLayerToString(buffer, bufferSize, tcpHeader, layerSize - sizeof(TCPHeader) - (uint32_t)*tcpHeader->optionsAndData + 1);
                else
                    PacketCraft::ConvertTCPLayerToString(buffer, bufferSize, tcpHeader, layerSize - sizeof(TCPHeader));
             
                file.write(buffer, PacketCraft::GetStrLen(buffer));
                break;
            }
            default:
            {
                free(buffer);
                file.close();
                LOG_ERROR(APPLICATION_ERROR, "unknown protocol detected!");
                return APPLICATION_ERROR;
            }

            memset(buffer, '\0', bufferSize);
        }
    }
    
    free(buffer);
    file.close();

    return NO_ERROR;
}