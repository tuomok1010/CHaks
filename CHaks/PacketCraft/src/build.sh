#!/bin/bash

Code="../../src/main.cpp ../../src/Utils.cpp ../../NetworkUtils.cpp ../../src/Packet.cpp ../../src/ARP.cpp ../../src/IPv4PingPacket.cpp"

# build object file
cd ../build/rel
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o utils.o ../../src/Utils.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o network_utils.o ../../src/NetworkUtils.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o packet.o ../../src/Packet.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o arp.o ../../src/ARP.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o ping.o ../../src/IPv4PingPacket.cpp
g++ -std=c++17 -Wall -D DEBUG_BUILD -fPIC -c -o ping6.o ../../src/IPv6PingPacket.cpp

# build shared library
g++ -shared -o ../lib/libpacketcraft.so utils.o network_utils.o packet.o arp.o ping.o ping6.o

cd ../../src