#!/bin/bash

Code="../../src/main.cpp ../../src/Utils.cpp ../../src/Packet.cpp ../../src/ARP.cpp"

cd ../build/rel
g++ -std=c++17 -Wall $Code -o PacketCraft
cd ../../src