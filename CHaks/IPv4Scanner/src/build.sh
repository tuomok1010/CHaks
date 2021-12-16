#!/bin/bash

Code="../../src/main.cpp ../../src/IPv4Scanner.cpp"
LibPath="../../../PacketCraft/build/lib/"
IncludePath="../../../PacketCraft/src/include/"
export LD_LIBRARY_PATH=$LibPath:$LD_LIBRARY_PATH


cd ../build/rel
g++ -L$LibPath -Wl,-rpath,$LibPath -Wall -o IPv4Scanner $Code -I$IncludePath -lpacketcraft
cd ../../src