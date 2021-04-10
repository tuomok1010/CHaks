#!/bin/bash

Code="../../src/main.cpp ../../src/Utils.cpp ../../src/Packet.cpp ../../src/ARP.cpp"

# build object file
cd ../build/rel
g++ -std=c++17 -Wall -fPIC -c -o utils.o ../../src/Utils.cpp
g++ -std=c++17 -Wall -fPIC -c -o packet.o ../../src/Packet.cpp
g++ -std=c++17 -Wall -fPIC -c -o arp.o ../../src/ARP.cpp

# build shared library
g++ -shared -o ../lib/libpacketcraft.so utils.o packet.o arp.o

cd ../../src