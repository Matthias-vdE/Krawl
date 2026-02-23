# Nftables + Krawl Integration

## Overview

This guide explains how to integrate **nftables** with Krawl to automatically block detected malicious IPs at the firewall level. Nftables is the modern replacement for iptables on newer Linux systems and provides more efficient IP set-based blocking.

## Architecture

```
Krawl detects malicious IPs
         ↓
Stores in database
         ↓
API endpoint
         ↓
Cron job fetches list
         ↓
Nftables firewall blocks IPs
         ↓
All traffic from banned IPs dropped
```

## Prerequisites

- Modern Linux system with nftables installed (Ubuntu 22+, Debian 12+, RHEL 9+)
- Krawl running with API accessible
- Root/sudo access
- Curl for HTTP requests
- Cron for scheduling

## When to Use Nftables

Check if your system uses nftables:

```bash
sudo nft list tables
```

If this shows tables, you're using nftables. If you get command not found, use iptables instead.

## Installation & Setup

### 1. Create the [krawl-nftables.sh](krawl-nftables.sh) script

```bash
#!/bin/bash


curl -s https://your-krawl-instance/your-dashboard-path/api/get_banlist?fwtype=iptables > /tmp/ips_to_ban.txt


sudo nft add set inet filter krawl_ban { type ipv4_addr \; } 2>/dev/null || true


while read -r ip; do
  [[ -z "$ip" ]] && continue
  sudo nft add element inet filter krawl_ban { "$ip" }
done < /tmp/ips_to_ban.txt


sudo nft add rule inet filter input ip saddr @krawl_ban counter drop 2>/dev/null || true


rm -f /tmp/ips_to_ban.txt
```

Make it executable:
```bash
sudo chmod +x ./krawl-nftables.sh
```

### 2. Test the Script

```bash
sudo ./krawl-nftables.sh
```

### 3. Schedule with Cron

Edit root crontab:
```bash
sudo crontab -e
```

Add this line to sync IPs every hour:

```bash
0 * * * * /path/to/krawl-nftables.sh
```

## Monitoring

### Check the Blocking Set

View blocked IPs:
```bash
sudo nft list set inet filter krawl_ban
```

Count blocked IPs:
```bash
sudo nft list set inet filter krawl_ban | grep "elements" | wc -w
```

### Check Active Rules

View all rules in the filter table:
```bash
sudo nft list table inet filter
```

Find Krawl-specific rules:
```bash
sudo nft list chain inet filter input | grep krawl_ban
```

### Monitor in Real-Time

Watch packets being dropped:
```bash
sudo nft list set inet filter krawl_ban -a
```

## Management Commands

### Manually Block an IP

```bash
sudo nft add element inet filter krawl_ban { 192.168.1.100 }
```

### Manually Unblock an IP

```bash
sudo nft delete element inet filter krawl_ban { 192.168.1.100 }
```

### List All Blocked IPs

```bash
sudo nft list set inet filter krawl_ban
```

### Clear All Blocked IPs

```bash
sudo nft flush set inet filter krawl_ban
```

### Delete the Rule

```bash
sudo nft delete rule inet filter input handle <handle>
```

## References

- [Nftables Official Documentation](https://wiki.nftables.org/)
- [Nftables Quick Reference](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)
- [Linux Kernel Netfilter Guide](https://www.kernel.org/doc/html/latest/networking/netfilter/)
- [Nftables Man Page](https://man.archlinux.org/man/nft.8)
