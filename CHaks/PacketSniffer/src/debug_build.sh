#!/bin/bash

Code="../../src/main.cpp ../../src/PacketSniffer.cpp"
LibPath="../../../PacketCraft/build/lib/"
IncludePath="../../../PacketCraft/src/include/"
export LD_LIBRARY_PATH=$LibPath:$LD_LIBRARY_PATH


cd ../build/debug
g++ -L$LibPath -Wl,-rpath,$LibPath -Wall -D DEBUG_BUILD -o PacketSniffer $Code -I$IncludePath -lpacketcraft
cd ../../src