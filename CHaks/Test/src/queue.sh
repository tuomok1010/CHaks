#!/bin/bash

nft 'add table inet my_table'
nft 'add chain inet my_table my_chain {type filter hook prerouting priority 0 ; }'

## filter for ipv4 and ipv6 packets
nft 'add rule inet my_table my_chain meta protocol {ip, ip6}'

## filter for both tcp and udp packets ## 
nft 'add rule inet my_table my_chain meta l4proto {tcp, udp}'


nft 'add rule inet my_table my_chain queue num 1'
echo 'table created. current active ruleset: '
nft 'list ruleset'