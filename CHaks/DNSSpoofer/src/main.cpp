#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include "DNSSpoofer.h"

#include <iostream>


int main(int argc, char** argv)
{
    int socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(socketFd == -1)
    {
        LOG_ERROR(APPLICATION_ERROR, "socket() error!");
        return APPLICATION_ERROR;
    }


    return NO_ERROR;
}