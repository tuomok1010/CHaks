#!/bin/bash

cd ../build/rel
g++ -std=c++17 -Wall ../../src/main.cpp ../../src/Utils.cpp ../../src/Packet.cpp -o PacketCraft
cd ../../src