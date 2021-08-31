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
    saveToFile(FALSE),
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

            // check the tcp payload data protocol
            if(PacketCraft::CompareStr(packetProtocolStr, "TCP") == TRUE)
            {
                TCPHeader* tcpHeader = (TCPHeader*)packet.GetLayerStart(i);
                uint32_t tcpDataSize = packet.GetLayerSize(i) - (tcpHeader->doff * 32 / 8);
                uint32_t tcpDataProtoInt = PacketCraft::GetTCPDataProtocol(tcpHeader, tcpDataSize);
                const char* tcpDataProtoStr = PacketCraft::ProtoUint32ToStr(tcpDataProtoInt);

                if(PacketCraft::CompareStr(tcpDataProtoStr, protocolsSupplied[j]) == TRUE)
                {
                    isValid = TRUE;
                }
            }
        }
    }

    if(isValid == TRUE)
    {
        if(saveToFile == TRUE)
        {
            char fullPath[PATH_MAX_SIZE]{};
            if(GetFullFilePath(packet, fullPath) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "GetFullFilePath() error!");
                return APPLICATION_ERROR;
            }

            std::cout << "full path is " << fullPath << std::endl;

            if(packet.Print(TRUE, fullPath) == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Print() error!");
                return APPLICATION_ERROR;
            }

            std::cout << "packet saved to file (" << packet.GetSizeInBytes() << " bytes) [press enter to stop]" << std::endl;
        }
        else
        {
            if(packet.Print() == APPLICATION_ERROR)
            {
                LOG_ERROR(APPLICATION_ERROR, "PacketCraft::Packet::Print() error!");
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

int CHaks::PacketSniffer::GetFullFilePath(const PacketCraft::Packet& packet, char* fullPathBuffer)
{
    char fileName[100]{};
    const char* packetNumStr = std::to_string(packetNumber).c_str();
    PacketCraft::CopyStr(fileName, sizeof(fileName), packetNumStr);

    std::cout << "packet num int is " << packetNumber << " packet num str is " << packetNumStr << std::endl;

    PacketCraft::CopyStr(fileName + PacketCraft::GetStrLen(packetNumStr), 1, "_");
    char* fileNamePtr = fileName + PacketCraft::GetStrLen(packetNumStr) + 1;

    for(unsigned int i = 0; i < packet.GetNLayers(); ++i)
    {
        const char* proto = PacketCraft::ProtoUint32ToStr(packet.GetLayerType(i));
        PacketCraft::CopyStr(fileNamePtr, PROTOCOL_NAME_SIZE, proto);
        fileNamePtr += PacketCraft::GetStrLen(proto);
        PacketCraft::CopyStr(fileNamePtr, 1, "_");
        ++fileNamePtr;

        // add the tcp payload data protocol to the filename
        if(PacketCraft::CompareStr(proto, "TCP") == TRUE)
        {
            TCPHeader* tcpHeader = (TCPHeader*)packet.GetLayerStart(i);
            uint32_t tcpDataSize = packet.GetLayerSize(i) - (tcpHeader->doff * 32 / 8);
            uint32_t tcpDataProtoInt = PacketCraft::GetTCPDataProtocol(tcpHeader, tcpDataSize);
            const char* tcpDataProtoStr = PacketCraft::ProtoUint32ToStr(tcpDataProtoInt);

            PacketCraft::CopyStr(fileNamePtr, PROTOCOL_NAME_SIZE, tcpDataProtoStr);
            fileNamePtr += PacketCraft::GetStrLen(tcpDataProtoStr);
            PacketCraft::CopyStr(fileNamePtr, 1, "_");
            ++fileNamePtr;
        }
    }

    PacketCraft::CopyStr(fileNamePtr, 5, ".txt");

    memcpy(fullPathBuffer, savePath, PacketCraft::GetStrLen(savePath));
    memcpy(fullPathBuffer + PacketCraft::GetStrLen(savePath), fileName, PacketCraft::GetStrLen(fileName) + 1);

    return NO_ERROR;
}