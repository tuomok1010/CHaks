#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#include <iostream>
#include <arpa/inet.h>

int main()
{
    sockaddr_in netMask{};
    sockaddr_in ipAddr{};

    int socketFd = socket(AF_INET, SOCK_RAW, htons(ETH_P_802_3));

    PacketCraft::GetNetworkMask(netMask, 2, socketFd);
    PacketCraft::PrintIPAddr(netMask, "mask: ", "\n");

    PacketCraft::GetIPAddr(ipAddr, "eth0");

    int nBits;
    PacketCraft::GetNumHostBits(nBits, ipAddr, "eth0", socketFd);
    std::cout << "num bits: " << nBits << std::endl;

    

    return NO_ERROR;
}