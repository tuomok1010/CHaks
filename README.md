# CHaks
WORK IN PROGRESS
only tested with a virtual machine Linux kali 5.14.0-kali4-amd64 (Host system windows 10)

Everything should work except FileInterceptor. Expect bugs.

NOTE: you will need libmnl and libnetfilter_queue installed.
You can install them with the following commands:


<code>sudo apt-get update</code>

<code>sudo apt-get install libmnl-dev</code>

<code>sudo apt-get install libnetfilter-queue-dev</code>

A more thorough documentation coming once the programs are more stable and/or when I manage to overcome my laziness.



## FileInterceptor
Before you use the program, do the following steps:

<b>1. Create a nft table with the following command:</b>

nft add table <IP_VERSION> <TABLE_NAME>

example for ipv4:

<code>nft add table ip my_table</code> 

example for ipv6:

<code>nft add table ip6 my_table</code>

<b>2. Create a chain for the table:</b>

nft 'add chain <IP_VERSION> <TABLE_NAME> <CHAIN_NAME> {type filter hook prerouting priority 0 ; }'

example for ipv4:

<code>nft 'add chain ip my_table my_chain {type filter hook prerouting priority 0 ; }'</code>

example for ipv6:

<code>nft 'add chain ip6 my_table my_chain {type filter hook prerouting priority 0 ; }'</code>

<b>3. Add rules to the chain:</b>

nft add rule <IP_VERSION> <TABLE_NAME> <CHAIN_NAME> meta l4proto tcp

nft add rule <IP_VERSION> <TABLE_NAME> <CHAIN_NAME> queue num <QUEUE_NUM>

example for ipv4:

<code>nft add rule ip my_table my_chain meta l4proto tcp</code>

<code>nft add rule ip my_table my_chain queue num 1</code>

example for ipv6:

<code>nft add rule ip6 my_table my_chain meta l4proto tcp</code>

<code>nft add rule ip6 my_table my_chain queue num 1</code>

<b>4. OPTIONAL: view the created table, chain and rules with the following command:</b>

<code>nft list ruleset</code>

<b>5. Start the program. Type "./FileInterceptor ?" to view the required arguments.</b>

<b>6. After using the program, you HAVE TO flush and delete the table you created:</b>

nft flush table <IP_VERSION> <TABLE_NAME>

nft delete table <IP_VERSION> <TABLE_NAME>

example for ipv4:

<code>nft flush table ip my_table</code>

<code>nft delete table ip my_table</code>

example for ipv6:

<code>nft flush table ip6 my_table</code>

<code>nft delete table ip6 my_table</code>

NOTE: for more information on nftables, visit https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
