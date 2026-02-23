#!/bin/bash
# This script fetches a list of malicious IPs from your Krawl instance and adds them to the iptables firewall to block incoming traffic from those IPs.

curl -s https://your-krawl-instance/api/get_banlist?fwtype=iptables | while read ip; do 
  iptables -C INPUT -s "$ip" -j DROP || iptables -A INPUT -s "$ip" -j DROP; 
done