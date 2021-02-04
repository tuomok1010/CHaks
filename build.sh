#!/bin/bash

cd build/rel
g++ -std=c++17 ../../src/main.cpp -o PacketCraft
cd ../../../