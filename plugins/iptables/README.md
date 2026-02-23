# Iptables + Krawl Integration

## Overview

This guide explains how to integrate **iptables** with Krawl to automatically block detected malicious IPs at the firewall level. The iptables integration fetches the malicious IP list directly from Krawl's API and applies firewall rules.

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
Iptables firewall blocks IPs
         ↓
All traffic from banned IPs dropped
```

## Prerequisites

- Linux system with iptables installed (typically pre-installed)
- Krawl running with API accessible
- Root/sudo access
- Curl or wget for HTTP requests
- Cron for scheduling (or systemd timer as alternative)

## Installation & Setup

### 1. Create the [krawl-iptables.sh](krawl-iptables.sh) script

```bash
#!/bin/bash

curl -s https://your-krawl-instance/your-dashboard-path/api/get_banlist?fwtype=iptables | while read ip; do 
  iptables -C INPUT -s "$ip" -j DROP || iptables -A INPUT -s "$ip" -j DROP; 
done
```

Make it executable:
```bash
sudo chmod +x ./krawl-iptables.sh
```

### 2. Test the Script

```bash
sudo ./krawl-iptables.sh
```

### 3. Schedule with Cron

Edit root crontab:
```bash
sudo crontab -e
```

Add this line to sync IPs every hour:

```bash
0 * * * * /path/to/krawl-iptables.sh
```

## How It Works

### When the Script Runs

1. **Fetch IPs** from Krawl API (`/api/get_banlist?fwtype=iptables`)
2. **Add new DROP rules** for each IP
3. **Rules are applied immediately** at kernel level

## Monitoring

### Check Active Rules

View all KRAWL-BAN rules:
```bash
sudo iptables -L KRAWL-BAN -n
```

Count blocked IPs:
```bash
sudo iptables -L KRAWL-BAN -n | tail -n +3 | wc -l
```

### Check Script Logs

```bash
sudo tail -f /var/log/krawl-iptables-sync.log
```

### Monitor in Real-Time

Watch dropped packets (requires kernel logging):
```bash
sudo tail -f /var/log/syslog | grep "IN=.*OUT="
```

## Management Commands

### Manually Block an IP

```bash
sudo iptables -A KRAWL-BAN -s 192.168.1.100 -j DROP
```

### Manually Unblock an IP

```bash
sudo iptables -D KRAWL-BAN -s 192.168.1.100 -j DROP
```

### List All Blocked IPs

```bash
sudo iptables -L KRAWL-BAN -n | grep DROP
```

### Clear All Rules

```bash
sudo iptables -F KRAWL-BAN
```

### Disable the Chain (Temporarily)

```bash
sudo iptables -D INPUT -j KRAWL-BAN
```

### Re-enable the Chain

```bash
sudo iptables -I INPUT -j KRAWL-BAN
```

### View Statistics

```bash
sudo iptables -L KRAWL-BAN -n -v
```

## Persistent Rules (Survive Reboot)

### Save Current Rules

```bash
sudo iptables-save > /etc/iptables/rules.v4
```

### Restore on Boot

Install iptables-persistent:
```bash
sudo apt-get install iptables-persistent
```

During installation, choose "Yes" to save current IPv4 and IPv6 rules.

To update later:
```bash
sudo iptables-save > /etc/iptables/rules.v4
sudo systemctl restart iptables
```

## Performance Considerations

### For Your Setup

- **Minimal overhead** — Iptables rules are processed at kernel level (very fast)
- **No logging I/O** — Blocked IPs are dropped before application sees them
- **Scales to thousands** — Iptables can efficiently handle 10,000+ rules

### Optimization Tips

1. **Use a custom chain** — Isolates Krawl rules from other firewall rules
2. **Schedule appropriately** — Every hour is usually sufficient; adjust based on threat level
3. **Monitor rule count** — Check periodically to ensure the script is working
4. **Consider IPSET** — For 10,000+ IPs, use ipset instead (more efficient)

### Using IPSET (Advanced)

For large-scale deployments, ipset is more efficient than individual iptables rules:

```bash
# Create ipset
sudo ipset create krawl-ban hash:ip

# Add IPs to ipset
while read ip; do
  sudo ipset add krawl-ban "$ip"
done

# Single iptables rule references the ipset
sudo iptables -I INPUT -m set --match-set krawl-ban src -j DROP
```

## Troubleshooting

### Script Says "Failed to fetch IP list"

Check API connectivity:
```bash
curl http://your-krawl-instance/api/get_banlist?fwtype=iptables
```

Verify:
- Krawl is running
- API URL is correct
- Firewall allows outbound HTTPS/HTTP
- No authentication required

### Iptables Rules Not Persisting After Reboot

Install and configure iptables-persistent:
```bash
sudo apt-get install iptables-persistent
sudo iptables-save > /etc/iptables/rules.v4
```

### Script Runs but No Rules Added

Check if chain exists:
```bash
sudo iptables -L KRAWL-BAN -n 2>&1 | head -1
```

Check logs for errors:
```bash
sudo grep ERROR /var/log/krawl-iptables-sync.log
```

Verify IP format in Krawl API response:
```bash
curl http://your-krawl-instance/api/get_banlist?fwtype=iptables | head -10
```

### Blocked Legitimate Traffic

Check what IPs are blocked:
```bash
sudo iptables -L KRAWL-BAN -n | grep -E [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
```

Unblock an IP:
```bash
sudo iptables -D KRAWL-BAN -s 203.0.113.50 -j DROP
```

Report false positive to Krawl administrators.

## Security Best Practices

1. **Limit API access** — Restrict `/api/get_banlist` to trusted networks (if internal use)
2. **Use HTTPS** — Fetch from HTTPS endpoint if available
3. **Verify TLS certificates** — Add `-k` only if necessary, not by default
4. **Rate limit cron jobs** — Don't run too frequently to avoid DoS
5. **Monitor sync logs** — Alert on repeated failures
6. **Backup rules** — Periodically backup `/etc/iptables/rules.v4`

## Integration with Krawl Workflow

Combined with fail2ban and iptables:

```
Real-time events (fail2ban)
         ↓
Immediate IP bans (temporary)
         ↓
Hourly sync (iptables cron)
         ↓
Permanent block until next rotation
         ↓
30-day cleanup cycle
```

## Manual Integration Example

Instead of cron, manually fetch and block:

```bash
# Fetch malicious IPs
curl -s http://your-krawl-instance/api/get_banlist?fwtype=iptables > /tmp/malicious_ips.txt

# Read and block each IP
while read ip; do
  sudo iptables -A KRAWL-BAN -s "$ip" -j DROP
done < /tmp/malicious_ips.txt

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

## References

- [Iptables Man Page](https://linux.die.net/man/8/iptables)
- [Iptables Essentials](https://www.digitalocean.com/community/tutorials/iptables-essentials-common-firewall-rules-and-commands)
- [Ipset Documentation](https://ipset.netfilter.org/)
- [Linux Firewall Administration Guide](https://www.kernel.org/doc/html/latest/networking/nf_conntrack-sysctl.html)
