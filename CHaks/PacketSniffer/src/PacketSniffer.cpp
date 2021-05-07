#include "PacketSniffer.h"

PacketSniff::PacketSniffer::PacketSniffer()
{

}

PacketSniff::PacketSniffer::~PacketSniffer()
{

}

bool32 PacketSniff::PacketSniffer::IsProtocolSupported(const char* protocol)
{
    for(int i = 0; i < N_PROTOCOLS_SUPPORTED; ++i)
    {   
        if(PacketCraft::CompareStr(supportedProtocols[i], protocol) == TRUE)
        {
            return TRUE;
        }
    }

    return FALSE;
}