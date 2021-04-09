#!/bin/bash

Code="../../src/main.cpp ../../src/Utils.cpp ../../src/Packet.cpp ../../src/ARP.cpp"

# build object file
cd ../build/rel
g++ -std=c++17 -Wall -fPIC -o PacketCraft.o $Code

# build shared library
g++ -shared -o ../lib/libpacketcraft.so PacketCraft.o

cd ../../src