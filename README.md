# Linux Digital Forensics & Incident Response (LDFIR)
### Post-Compromise Analysis Guide

> **Scope:** This guide walks through triage, evidence collection, and analysis after a Linux system has been compromised. Commands assume root or sudo access. Work from a **trusted, read-only live environment** where possible — a compromised kernel's tools may lie to you.

---

## Table of Contents

1. [First Response Principles](#1-first-response-principles)
2. [Volatile Data Collection (Do This First)](#2-volatile-data-collection-do-this-first)
3. [User & Authentication Analysis](#3-user--authentication-analysis)
4. [Process & Network Analysis](#4-process--network-analysis)
5. [Persistence Mechanisms](#5-persistence-mechanisms)
6. [Filesystem & File Analysis](#6-filesystem--file-analysis)
7. [Log Analysis](#7-log-analysis)
8. [Memory Forensics](#8-memory-forensics)
9. [Malware & Rootkit Detection](#9-malware--rootkit-detection)
10. [Timeline Reconstruction](#10-timeline-reconstruction)
11. [Containment & Remediation](#11-containment--remediation)
12. [Evidence Preservation](#12-evidence-preservation)

---

## 1. First Response Principles

**Do not panic. Do not reboot.** Rebooting destroys volatile evidence (RAM, active connections, running processes).

### Immediate decisions

```
Is the system actively being used by an attacker right now?
├── YES → Isolate network first, preserve volatile data second
└── NO  → Preserve volatile data before anything else
```

### Isolate the network without rebooting

```bash
# Drop all traffic immediately
sudo iptables -I INPUT -j DROP
sudo iptables -I OUTPUT -j DROP
sudo iptables -I FORWARD -j DROP

# Or take the interface down
sudo ip link set eth0 down

# Unplug the cable / disable WiFi as a last resort if commands fail
```

### Record your environment before touching anything

```bash
date -u                        # timestamp everything in UTC
uname -a                       # kernel version
hostname
id                             # who you are running as
uptime                         # how long the system has been running
```

---

## 2. Volatile Data Collection (Do This First)

Volatile data disappears on reboot. Collect it immediately, in this order.

### System time & uptime

```bash
date -u
uptime
cat /proc/uptime
```

### Running processes

```bash
ps auxf                        # full process tree with hierarchy
ps -eo pid,ppid,user,stat,start,time,comm,args
ls -la /proc/*/exe 2>/dev/null # resolve actual binary for each PID
```

### Open network connections

```bash
ss -antpue                     # all TCP/UDP connections with PIDs
netstat -antpue                # alternative if ss unavailable
lsof -i                        # files/processes tied to network
cat /proc/net/tcp              # raw kernel TCP table (hex)
cat /proc/net/tcp6
cat /proc/net/udp
```

### Logged-in users

```bash
who
w
last -a                        # login history
lastb                          # failed logins
```

### Loaded kernel modules

```bash
lsmod
cat /proc/modules
```

### ARP & routing table

```bash
arp -a
ip neigh
ip route
ip addr
```

### Environment variables for all processes

```bash
for pid in /proc/[0-9]*/environ; do
    echo "=== $pid ===";
    cat "$pid" 2>/dev/null | tr '\0' '\n';
done
```

### Open file descriptors

```bash
lsof -n                        # all open files
lsof +L1                       # files open but deleted (common attacker trick)
```

---

## 3. User & Authentication Analysis

### Check for new or modified users

```bash
cat /etc/passwd
cat /etc/shadow                # look for unusual hashes or accounts
cat /etc/group
# Look for UID 0 accounts other than root
awk -F: '($3 == 0) {print}' /etc/passwd
```

### SSH keys

```bash
# Check authorized_keys for every user
for home in /root /home/*; do
    echo "=== $home ===";
    cat "$home/.ssh/authorized_keys" 2>/dev/null;
done

# Look for recently modified authorized_keys
find / -name "authorized_keys" -newer /etc/passwd 2>/dev/null
```

### Sudo access

```bash
cat /etc/sudoers
ls -la /etc/sudoers.d/
sudo -l -U <username>          # what can a specific user run
```

### Login history & auth logs

```bash
last -Faixw                    # full login history with IPs
lastb -Faixw                   # failed attempts
grep "Accepted\|Failed\|Invalid" /var/log/auth.log
grep "sudo" /var/log/auth.log
journalctl _SYSTEMD_UNIT=sshd.service --since "7 days ago"
```

### PAM backdoor indicators

```bash
# Check PAM config for unauthorized changes
ls -la /etc/pam.d/
find /lib/security/ -newer /etc/passwd 2>/dev/null
find /lib64/security/ -newer /etc/passwd 2>/dev/null
```

---

## 4. Process & Network Analysis

### Find processes with no associated binary (deleted/replaced)

```bash
# Processes where the binary has been deleted
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Processes running from /tmp, /dev/shm, /var/tmp (major red flag)
ls -la /proc/*/exe 2>/dev/null | grep -E "tmp|shm"
```

### Processes listening on unusual ports

```bash
ss -tlnp
# Cross-reference with known services
# Any port above 1024 run by root is suspicious
```

### Check parent-child relationships for anomalies

```bash
pstree -p -a -l               # full tree with PIDs and args
# Common suspicious patterns:
# apache2 → bash → nc
# cron → sh → wget
# sshd → bash (but user never logged in)
```

### Network connections to external IPs

```bash
ss -antpe | grep ESTABLISHED
# Get geolocation of remote IPs (requires curl/internet)
for ip in $(ss -tn | awk '/ESTABLISHED/ {print $5}' | cut -d: -f1 | sort -u); do
    echo "$ip: $(curl -s ipinfo.io/$ip/country 2>/dev/null)"
done
```

### DNS queries (if systemd-resolved)

```bash
journalctl -u systemd-resolved --since "24 hours ago"
cat /var/log/syslog | grep -i dns
```

---

## 5. Persistence Mechanisms

These are the most common places attackers leave backdoors.

### Cron jobs

```bash
crontab -l                     # current user
crontab -l -u root
cat /etc/crontab
ls -la /etc/cron.*
find /var/spool/cron/ -type f  # all user crontabs
```

### Systemd services

```bash
systemctl list-units --type=service --all
systemctl list-unit-files --type=service
# Look for recently created or modified unit files
find /etc/systemd /usr/lib/systemd /lib/systemd -name "*.service" \
     -newer /etc/passwd 2>/dev/null
```

### Init / rc scripts

```bash
ls -la /etc/init.d/
ls -la /etc/rc.local
cat /etc/rc.local
ls -la /etc/rc*.d/
```

### Shell startup files

```bash
for f in /root/.bashrc /root/.bash_profile /root/.profile \
          /etc/profile /etc/bash.bashrc /etc/environment; do
    echo "=== $f ==="; cat "$f" 2>/dev/null;
done

find /home -name ".bashrc" -o -name ".profile" -o -name ".zshrc" | \
    xargs grep -l "wget\|curl\|nc\|bash -i\|/dev/tcp" 2>/dev/null
```

### SUID/SGID binaries (privilege escalation persistence)

```bash
find / -perm -4000 -type f 2>/dev/null | sort   # SUID
find / -perm -2000 -type f 2>/dev/null | sort   # SGID
# Compare against a known-good baseline if available
```

### Writable directories in PATH

```bash
echo $PATH | tr ':' '\n' | xargs ls -ld 2>/dev/null | grep -v "^d..x..x..x"
```

### /etc/ld.so.preload (LD_PRELOAD backdoor)

```bash
cat /etc/ld.so.preload        # should almost always be empty
ls -la /etc/ld.so.conf.d/
ldconfig -p                   # list cached shared libraries
```

### Kernel modules (rootkits)

```bash
lsmod
# Check for modules not in /lib/modules/$(uname -r)/
find /lib/modules/$(uname -r)/ -name "*.ko" > /tmp/known_modules.txt
lsmod | awk '{print $1}' | tail -n +2 > /tmp/loaded_modules.txt
diff /tmp/known_modules.txt /tmp/loaded_modules.txt
```

---

## 6. Filesystem & File Analysis

### Recently modified files

```bash
# Files modified in the last 24 hours
find / -xdev -mtime -1 -type f 2>/dev/null | grep -v proc | grep -v sys

# Files modified in the last 7 days, sorted
find / -xdev -mtime -7 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' \
    2>/dev/null | sort | grep -v proc | grep -v sys

# Specifically check sensitive locations
find /etc /bin /sbin /usr/bin /usr/sbin /lib /lib64 \
     -newer /etc/passwd -type f 2>/dev/null
```

### Files in unusual locations

```bash
# Executables in /tmp, /var/tmp, /dev/shm
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null

# Hidden files and directories
find / -name ".*" -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# Large files that shouldn't be large
find / -xdev -size +100M -type f 2>/dev/null | grep -v proc
```

### File integrity checks

```bash
# If aide is installed
aide --check

# If tripwire is installed
tripwire --check

# Manual hash check of critical binaries
for bin in /bin/ls /bin/ps /bin/netstat /usr/bin/ssh /usr/sbin/sshd; do
    echo "$bin: $(sha256sum $bin 2>/dev/null)"
done

# Compare against package manager's expected hashes
rpm -Va 2>/dev/null            # RPM-based systems
dpkg --verify 2>/dev/null      # Debian-based systems
```

### Deleted files still open (classic attacker trick)

```bash
# Attackers often delete their binary but keep it running
lsof +L1 2>/dev/null
# Recover the binary from /proc
cp /proc/<PID>/exe /tmp/recovered_binary
file /tmp/recovered_binary
strings /tmp/recovered_binary | head -100
```

### Check for web shells

```bash
find /var/www /srv /opt /usr/share/nginx /usr/share/apache2 \
     -name "*.php" -o -name "*.jsp" -o -name "*.aspx" 2>/dev/null | \
     xargs grep -l "exec\|system\|passthru\|shell_exec\|base64_decode" 2>/dev/null
```

---

## 7. Log Analysis

> **Note:** Logs may have been cleared or tampered with. Absence of logs is itself evidence.

### Check if logs were wiped

```bash
ls -la /var/log/wtmp           # should not be 0 bytes on an active system
ls -la /var/log/btmp
ls -la /var/log/lastlog
ls -la /var/log/auth.log
stat /var/log/auth.log         # check modification time vs creation time
```

### Syslog / system messages

```bash
grep -i "error\|fail\|warn\|crit\|attack\|invalid" /var/log/syslog | tail -200
grep -i "segfault\|kernel\|oops\|panic" /var/log/kern.log
```

### Authentication logs

```bash
grep "Accepted password\|Accepted publickey" /var/log/auth.log
grep "FAILED\|Failed\|Invalid user" /var/log/auth.log
grep "sudo\|su\[" /var/log/auth.log
```

### Bash history (may be cleared)

```bash
cat /root/.bash_history
cat /home/*/.bash_history
# Also check alternative history files
cat /root/.zsh_history
cat /root/.python_history

# History files that were truncated (cleared)
ls -la /home/*/.bash_history /root/.bash_history
# 0 bytes or very recent mtime = likely wiped
```

### Journald (systemd logs)

```bash
journalctl --since "7 days ago" --no-pager | grep -i "fail\|error\|denied"
journalctl -u ssh --since "24 hours ago"
journalctl -u cron --since "24 hours ago"
journalctl --list-boots                   # previous boot sessions
journalctl -b -1                          # logs from last boot
```

### Apache / Nginx logs

```bash
grep -E "POST|PUT|CONNECT" /var/log/apache2/access.log | tail -200
grep " 500 \| 403 \| 401 " /var/log/nginx/access.log | tail -200
# Look for web shell activity
grep -E "cmd=|exec=|shell=|passthru" /var/log/apache2/access.log
```

---

## 8. Memory Forensics

### Dump process memory

```bash
# Dump memory regions of a suspicious process
cat /proc/<PID>/maps           # memory map
cat /proc/<PID>/smaps          # detailed memory usage

# Dump a specific memory region (get range from maps)
dd if=/proc/<PID>/mem bs=1 skip=$((0xSTART)) count=$((0xEND - 0xSTART)) \
   of=/tmp/memdump.bin 2>/dev/null

# Extract strings from process memory
strings /proc/<PID>/mem 2>/dev/null | grep -E "http|/tmp|bash|nc |wget|curl"
```

### Full memory capture (requires LiME or similar)

```bash
# Install LiME kernel module (from a trusted external source)
insmod lime.ko "path=/mnt/usb/memory.lime format=lime"

# Analyze with Volatility3 (on separate forensic workstation)
python3 vol.py -f memory.lime linux.pslist
python3 vol.py -f memory.lime linux.netstat
python3 vol.py -f memory.lime linux.bash
```

---

## 9. Malware & Rootkit Detection

### Check for hidden processes (PID gaps)

```bash
# Compare /proc PIDs vs ps output
diff <(ls /proc | grep -E '^[0-9]+$' | sort -n) \
     <(ps ax | awk '{print $1}' | grep -E '^[0-9]+$' | sort -n)
# Any PID in /proc but not in ps = hidden by rootkit
```

### Check for hidden network connections

```bash
# Compare ss vs /proc/net
ss -antpe > /tmp/ss_output.txt
cat /proc/net/tcp > /tmp/proc_tcp.txt
# Entries in /proc/net/tcp not in ss = rootkit hiding connections
```

### inotify / fanotify watchers (EDR or attacker tools)

```bash
# Check which processes hold filesystem watchers
for pid in /proc/[0-9]*/fdinfo/*; do
    grep -l "inotify\|fanotify" "$pid" 2>/dev/null
done
# Resolve PID: echo $pid | grep -oP '(?<=/proc/)\d+'
```

### Check preloaded libraries (LD_PRELOAD rootkits)

```bash
cat /etc/ld.so.preload
cat /proc/<suspicious_PID>/environ | tr '\0' '\n' | grep LD_PRELOAD
```

### Scan with chkrootkit / rkhunter

```bash
# Run from trusted read-only media ideally
chkrootkit
rkhunter --check --skip-keypress
```

### Detect kernel-level hooks

```bash
# Check syscall table for modifications (if you have a known-good baseline)
# Use SystemTap or eBPF tools for live analysis
# Or compare /proc/kallsyms addresses against a known-good kernel build
sudo grep "sys_call_table" /proc/kallsyms
```

---

## 10. Timeline Reconstruction

### Build a filesystem timeline

```bash
# mactime-style timeline using find
find / -xdev -printf "%A@ %T@ %C@ %m %n %u %g %s %p\n" 2>/dev/null \
    > /tmp/filesystem_timeline.txt

# Sort by modification time
sort -n /tmp/filesystem_timeline.txt | tail -500

# Convert to human-readable
find / -xdev -printf "%TY-%Tm-%Td %TH:%TM:%TS %p\n" 2>/dev/null | \
    sort | grep -v "/proc\|/sys" > /tmp/timeline_readable.txt
```

### Correlate with log timestamps

```bash
# Pull timestamps from auth log and match against file changes
grep "May 17" /var/log/auth.log | head -50

# Find all files touched around a suspicious login time
find / -xdev -newermt "2026-05-17 02:00" ! -newermt "2026-05-17 04:00" \
    2>/dev/null | grep -v proc | grep -v sys
```

### Check inode change times (ctime — harder to fake)

```bash
# ctime is updated on any metadata change (rename, chmod, etc.)
# stat shows all three: atime, mtime, ctime
stat /bin/ls
stat /usr/bin/sudo

# Find files with ctime in a suspicious window
find /bin /sbin /usr/bin /usr/sbin \
     -ctime -7 2>/dev/null
```

---

## 11. Containment & Remediation

### Immediate containment checklist

```bash
# 1. Isolate network
sudo iptables -I INPUT -j DROP
sudo iptables -I OUTPUT -j DROP

# 2. Kill attacker sessions (find their PID first)
who -a                         # find their TTY
pkill -9 -t pts/1              # kill session on pts/1

# 3. Revoke compromised SSH keys
# Edit /home/<user>/.ssh/authorized_keys and remove attacker key

# 4. Change all passwords
passwd root
passwd <compromised_user>

# 5. Rotate SSH host keys
rm /etc/ssh/ssh_host_*
ssh-keygen -A

# 6. Block attacker IP
sudo iptables -I INPUT -s <attacker_ip> -j DROP
```

### Remove persistence

```bash
# Remove malicious cron jobs
crontab -r                     # remove ALL cron for current user
crontab -r -u <user>           # specific user

# Disable malicious service
systemctl stop <malicious_service>
systemctl disable <malicious_service>
rm /etc/systemd/system/<malicious_service>.service

# Remove LD_PRELOAD entries
echo "" > /etc/ld.so.preload
ldconfig

# Remove malicious kernel module
rmmod <module_name>
# Then blacklist it permanently
echo "blacklist <module_name>" >> /etc/modprobe.d/blacklist.conf
```

---

## 12. Evidence Preservation

### Hash everything before you touch it

```bash
sha256sum /var/log/auth.log > /tmp/evidence_hashes.txt
sha256sum /var/log/syslog >> /tmp/evidence_hashes.txt
sha256sum /etc/passwd >> /tmp/evidence_hashes.txt
sha256sum /etc/shadow >> /tmp/evidence_hashes.txt
```

### Disk image (do on a live system before shutdown)

```bash
# Image to a remote host over SSH
sudo dd if=/dev/sda bs=4M | gzip | ssh user@forensic-host "cat > /cases/disk.img.gz"

# Or to local USB (mount it first)
sudo dd if=/dev/sda bs=4M | gzip > /mnt/usb/disk.img.gz

# Verify image integrity
sha256sum /mnt/usb/disk.img.gz
```

### Package volatile data for transport

```bash
mkdir /tmp/ir_$(date +%Y%m%d_%H%M%S)
IR_DIR="/tmp/ir_$(date +%Y%m%d_%H%M%S)"

ps auxf > "$IR_DIR/processes.txt"
ss -antpue > "$IR_DIR/network.txt"
lsmod > "$IR_DIR/modules.txt"
last -Faixw > "$IR_DIR/logins.txt"
find / -xdev -mtime -7 -type f 2>/dev/null > "$IR_DIR/recent_files.txt"
cp /var/log/auth.log "$IR_DIR/"
cp /var/log/syslog "$IR_DIR/"
cp /etc/passwd "$IR_DIR/"
cp /etc/shadow "$IR_DIR/"
sha256sum "$IR_DIR"/* > "$IR_DIR/HASHES.txt"

tar czf "/tmp/ir_evidence_$(date +%Y%m%d).tar.gz" "$IR_DIR"
```

---

## Quick Reference: Red Flags Checklist

| Indicator | Command to check |
|-----------|-----------------|
| Processes with deleted binaries | `lsof +L1` |
| UID 0 accounts not named root | `awk -F: '($3==0)' /etc/passwd` |
| SUID files in /tmp | `find /tmp -perm -4000` |
| Unusual kernel modules | `lsmod` vs known baseline |
| Outbound connections to unknown IPs | `ss -antpe` |
| Wiped log files | `ls -la /var/log/wtmp` |
| Cron jobs running scripts from /tmp | `crontab -l` |
| /etc/ld.so.preload not empty | `cat /etc/ld.so.preload` |
| Unauthorized SSH keys | `cat ~/.ssh/authorized_keys` |
| Hidden processes (PID gaps) | diff `/proc` vs `ps` |

---

*Always work from a trusted environment where possible. A compromised kernel can hide processes, files, and connections from standard tools. When in doubt, boot from a clean live USB and mount the suspect filesystem read-only.*

