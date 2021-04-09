#!/bin/bash

Code="../../src/main.cpp ../../src/Utils.cpp ../../src/Packet.cpp ../../src/ARP.cpp"

cd ../build/debug
g++ -std=c++17 -Wall -D DEBUG_BUILD $Code -o PacketCraft
cd ../../src