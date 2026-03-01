#!/bin/bash

# Fetch malicious IPs to temporary file
curl -s https://your-krawl-instance/your-dashboard-path/api/get_banlist?fwtype=iptables > /tmp/ips_to_ban.txt

# Create the set if it doesn't exist
sudo nft add set inet filter krawl_ban { type ipv4_addr \; } 2>/dev/null || true

# Add IPs to the set
while read -r ip; do
  [[ -z "$ip" ]] && continue
  sudo nft add element inet filter krawl_ban { "$ip" }
done < /tmp/ips_to_ban.txt

# Create the rule if it doesn't exist
sudo nft add rule inet filter input ip saddr @krawl_ban counter drop 2>/dev/null || true

# Cleanup
rm -f /tmp/ips_to_ban.txt