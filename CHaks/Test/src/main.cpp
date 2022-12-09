#include "../../../../PacketCraft/PacketCraft/src/include/PCInclude.h"

#include <iostream>

  
int main(int argc, char** argv)
{
    int queueNum{1};
    PacketCraft::PacketFilterQueue packetQueue(queueNum, AF_BRIDGE);
    if(packetQueue.Init() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ERROR");
        return APPLICATION_ERROR;
    }
    else
    {
        std::cout << "NO ERROR" << std::endl;
    }

    return NO_ERROR;
 } 