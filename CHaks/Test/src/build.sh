#!/bin/bash

Code="../../src/main.cpp"
LibPath="/home/tuomok/Projects/CHaks/CHaks/PacketCraft/build/lib/"
IncludePath="/home/tuomok/Projects/CHaks/CHaks/PacketCraft/src/include/"
export LD_LIBRARY_PATH=$LibPath:$LD_LIBRARY_PATH


cd ../build/rel
g++ -L$LibPath -Wl,-rpath,$LibPath -Wall -o Test $Code -I$IncludePath -lpacketcraft
cd ../../src