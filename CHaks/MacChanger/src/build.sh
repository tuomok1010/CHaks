#!/bin/bash

Code="../../src/main.cpp"
LibPath="/home/kali/Projects/CHaks/CHaks/PacketCraft/build/lib/"
IncludePath="/home/kali/Projects/CHaks/CHaks/PacketCraft/src/include/"
export LD_LIBRARY_PATH=$LibPath:$LD_LIBRARY_PATH


cd ../build/rel
g++ -L$LibPath -Wl,-rpath,$LibPath -Wall -o MacChanger $Code -I$IncludePath -lpacketcraft
cd ../../src