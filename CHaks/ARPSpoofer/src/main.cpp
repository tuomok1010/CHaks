#include "/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/PCInclude.h"
#include <netinet/in.h>

int main()
{

    sockaddr_in testAddr;
    PacketCraft::GetIPAddr(testAddr, "eth0");
    PacketCraft::PrintIPAddr(testAddr, "my IP: ", "\n");



    return 0;
}