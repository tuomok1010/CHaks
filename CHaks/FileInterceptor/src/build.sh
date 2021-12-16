#!/bin/bash

Code="../../src/main.cpp ../../src/FileInterceptor.cpp"
LibPath="../../../PacketCraft/build/lib/"
IncludePath="../../../PacketCraft/src/include/"
export LD_LIBRARY_PATH=$LibPath:$LD_LIBRARY_PATH


cd ../build/rel
g++ -L$LibPath -Wl,-rpath,$LibPath -Wall -o FileInterceptor $Code -I$IncludePath -lpacketcraft
cd ../../src