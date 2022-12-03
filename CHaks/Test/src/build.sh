#!/bin/bash

Code="../../src/main.cpp"
LibPath="../../../../../PacketCraft/PacketCraft/build/lib/"
IncludePath="../../../../../PacketCraft/PacketCraft/src/include/"
export LD_LIBRARY_PATH=$LibPath:$LD_LIBRARY_PATH


cd ../build/rel
g++ -L$LibPath -Wl,-rpath,$LibPath -Wall -o Test $Code -I$IncludePath -lpacketcraft -lnetfilter_queue
cd ../../src