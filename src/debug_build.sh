#!/bin/bash

cd ../build/debug
g++ -std=c++17 -Wall -D DEBUG_BUILD ../../src/main.cpp ../../src/Utils.cpp ../../src/Packet.cpp -o PacketCraft
cd ../../src