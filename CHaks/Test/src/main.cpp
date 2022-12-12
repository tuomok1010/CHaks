#include "../../../../PacketCraft/PacketCraft/src/include/PCInclude.h"

#include <iostream>

bool FilterPacket(const PacketCraft::Packet& packet)
{
    return true;
}

int EditPacket(PacketCraft::Packet& packet)
{
    return NO_ERROR;
}
  
int main(int argc, char** argv)
{
    int queueNum{1};
    int af{AF_INET};
    PacketCraft::PacketFilterQueue packetQueue;

    if(packetQueue.Init(queueNum, af, FilterPacket, EditPacket, PacketCraft::PC_ACCEPT, PacketCraft::PC_ACCEPT) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "PacketCraft::PacketFilterQueue::Init() error!");
        return APPLICATION_ERROR;
    }
    else
    {
        std::cout << "NO ERROR" << std::endl;
    }

    return NO_ERROR;
 } 