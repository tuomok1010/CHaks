#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#include <netinet/in.h> 

#include <iostream>

int main(int argc, char** argv)
{
    int socketFd = socket(PF_PACKET, SOCK_RAW, ETH_P_IP);
    const char* interfaceName = "eth0";
    const char* targetIP = "10.0.2.1";

    char myIPStr[INET_ADDRSTRLEN]{};
    if(PacketCraft::GetIPAddr(myIPStr, interfaceName, AF_INET) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "GetIPAddr() error!");
        return APPLICATION_ERROR;
    }

    char myMACStr[ETH_ADDR_STR_LEN]{};
    if(PacketCraft::GetMACAddr(myMACStr, interfaceName, socketFd) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "GetMACAddr() error!");
        return APPLICATION_ERROR;
    }

    char targetMACStr[ETH_ADDR_STR_LEN]{};
    if(PacketCraft::GetARPTableMACAddr(socketFd, interfaceName, targetIP, targetMACStr) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "GetARPTableMACAddr() error!");
        return APPLICATION_ERROR;
    }

    PacketCraft::IPv4PingPacket pingPacket;
    if(pingPacket.Create(myMACStr, targetMACStr, myIPStr, targetIP, PingType::ECHO_REQUEST) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::IPv4PingPacket::Create() error!");
        return APPLICATION_ERROR;
    }

    if(pingPacket.PrintPacketData() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::IPv4PingPacket::PrintPacketData() error!");
        return APPLICATION_ERROR;
    }

    return NO_ERROR;
}