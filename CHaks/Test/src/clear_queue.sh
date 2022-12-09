nft flush table inet my_table
nft delete table inet my_table
echo 'table flushed and deleted. current active ruleset:'
nft list ruleset