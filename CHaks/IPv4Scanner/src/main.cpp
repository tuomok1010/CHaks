#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"

#include <iostream>
#include <arpa/inet.h>

int ProcessArgs(int argc, char** argv)
{
    
}

int main(int argc, char** argv)
{

    int socketFd = socket(AF_INET, SOCK_RAW, htons(ETH_P_802_3));

    sockaddr_in networkAddr{};
    PacketCraft::GetNetworkAddr(networkAddr, "eth0", socketFd);

    return NO_ERROR;
}