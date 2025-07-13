for example in filter-ethernet atomic-replace firewall add-rules; do
	echo "Calling example ${example}"
	nft flush ruleset
	if [[ ${example} = atomic-replace ]]; then
		nft add table inet example-table
		nft add chain inet example-table chain-for-incoming-packets '{ type filter hook input priority filter; policy drop; }'
		nft add rule inet example-table chain-for-incoming-packets tcp dport 1234 accept
	fi
	./target/release/examples/${example} || exit 1
	nft list ruleset
	echo "Example ${example} done"
done
