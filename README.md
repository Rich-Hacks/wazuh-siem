# Wazuh SIEM on a Proxmox Homelab — Runbook

> **🌐 PUBLIC / SANITISED VERSION.** Addresses, MACs, mail domains and account names are placeholders (`10.0.0.0/24` management LAN, `example.com`). No secrets appear in this document. Guest IDs and hostnames are real — they carry no sensitive information. Substitute your own values throughout.

| | |
|---|---|
| **Maintainer** | Richard Carragher (RC COMMS) |
| **Last updated** | 18 October 2026 |
| **Document version** | 1.1 |
| **Wazuh** | 4.14.8 (manager, indexer, dashboard, filebeat, agents — all version-pinned) |
| **Manager** | All-in-one VM `gullion` on the compute node, `10.0.0.44` |
| **Classification** | Public |

Related: `proxmox-infrastructure-PUBLIC.md`, `ARCHITECTURE-PUBLIC.md`.

---

## 1. Scope and design

Wazuh gives the cluster one place for host logs, file-integrity monitoring (FIM), configuration assessment (SCA), package/vulnerability inventory and alerting. Design rules:

- **All-in-one VM**, not an LXC: Wazuh 4.14 central components support Ubuntu/RHEL, and OpenSearch needs `vm.max_map_count` tuning that an unprivileged CT cannot set.
- **Version lock-step.** Agents must never be newer than the manager. Every package is pinned and held; upgrades are deliberate (manager first), never via the Ultimate Updater.
- **Signal over volume.** Email only at level ≥12; FIM and auditd scoped to the PVE control plane; no blanket `execve` auditing.
- **No new exposure.** Indexer and API stay on loopback / behind the guest firewall; the mail relay listens on loopback only.

## 2. Manager — VM 130 `gullion`

| Property | Value |
|---|---|
| OS | Ubuntu 24.04.5 LTS |
| Resources | 4 cores, 8192 MB **balloon 0** (OpenSearch heap must not be reclaimed), `scsi0 vmstorage:vm-130-disk-0` 120 G ext4 |
| Network | `vmbr0`, `<MAC>`, 10.0.0.44 static (`enp6s18`), `firewall=1` |
| Install | `wazuh-install.sh -a` (all-in-one) |
| Listeners | Agents 1514/1515 · dashboard 443 (self-signed) · indexer 9200/9300 on 127.0.0.1 · API 55000 blocked by `130.fw` · Postfix 25 on 127.0.0.1/::1 |
| Guest firewall `130.fw` | DROP default; 1514–1515/tcp, 443/tcp, 22/tcp, ICMP from 10.0.0.0/24 (covers the tailnet via the subnet-router container and the monitoring Pi) |
| Backups | Weekly vzdump (snapshot mode) with the node's other guests; dumps mirrored to a second node |
| Monitoring | Uptime Kuma — HTTPS keyword, TLS ignored, 60 s (cert-expiry notification off) |
| Credentials | All in a password manager as **separate** entries: dashboard `admin`, the enrolment password, and a dedicated mail-provider app password for the relay. The installer's generated set stays in `/root/wazuh-install-files.tar` (600 root) |
| Retention | ISM policy `wazuh-alerts-90d` (template `wazuh-alerts-*`, delete at 90 days) |

**Capacity reading.** With balloon 0, PVE's summary graph shows ~100 % memory — that is guest page cache. Judge from inside the guest: on 12 Oct 2026 with 30 agents, `free -m` *available* 5 GiB, swap unused, indexer `java` RSS 1.6 GiB, 0 OOM kills. Watch weekly:

```bash
free -m; swapon --show; sudo du -sh /var/lib/wazuh-indexer; journalctl -k --since -7d | grep -ci 'out of memory'
```

## 3. Agent estate

**30 Active** = manager (000) + 29 agents, all `4.14.8-1`, held.

| IDs | Hosts | Phase |
|---|---|---|
| 001–003 | pve, pve2, pve3 | 1 (11 Oct) |
| 004–011 | `eagle`, `fedhome`, CT 121 bencrom, CT 131 nephin, CT 133 croaghaun, CT 112 immich, CT 134 beenkeragh, CT 101 oriel | 2 (11 Oct) |
| 012–017 | pve: CT 106 commedagh, 114 shanlieve, 115 doan, 116 errigal, 119 meelmore, 120 meelbeg | 3 (12 Oct) |
| 018–023 | pve2: CT 104 donard, 105 slievemore, 109 knockbrinnea, 117 conavalla, 118 beara, 141 eurooffice | 3 (12 Oct) |
| 024–029 | pve3: CT 123 bearnagh, 124 lamagan, 125 chimneyrock, 126 carn, 127 spelga, 129 pigeonrock | 3 (12 Oct) |

**Deliberate exclusions:** CT 132 `knockmore` (DB, 2 GiB, swap 0 — no headroom to give away); CT 122 `binnian` (at its 4 GiB cap after the Plex OOM loop — re-assess ~19 Oct); CT 103 `iveagh` (256 MiB, retiring). `fedhome`: Wazuh repo disabled after install so `dnf` cannot upgrade the agent.

### 3.1 Headroom check before enrolling CTs

An agent costs ~30–60 MiB RSS. Run on each node; enrol only with >150 MiB headroom (`memory.current` includes page cache, so it is an upper bound):

```bash
for id in $(pct list | awk 'NR>1 && $2=="running"{print $1}'); do c=/sys/fs/cgroup/lxc/$id; [ -r $c/memory.current ] || continue; cur=$(( $(cat $c/memory.current)/1048576 )); max=$(cat $c/memory.max); [ "$max" = max ] && maxm=unl || maxm=$(( max/1048576 )); printf "%-4s %-14s %5s / %5s MiB\n" $id "$(pct config $id | awk '/^hostname/{print $2}')" $cur $maxm; done
```

### 3.2 Enrolment (Debian/Ubuntu CTs, from the host)

1. Enrolment secret into a root-only file on the node (typed, never echoed or pasted into chat):

```bash
install -m 600 /dev/null /root/.wazuh-enrol && read -rsp 'Wazuh enrolment password: ' p && printf '%s' "$p" > /root/.wazuh-enrol && unset p && echo && wc -c < /root/.wazuh-enrol
```

2. Enrol a list of CTs (repo key dearmoured — gotcha W2; pinned and held):

```bash
for id in 106 114 115; do n=$(pct exec $id -- hostname); echo "== $id $n"; pct exec $id -- env WAZUH_MANAGER=10.0.0.44 WAZUH_REGISTRATION_PASSWORD="$(cat /root/.wazuh-enrol)" WAZUH_AGENT_NAME="$n" bash -c 'set -euo pipefail; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq curl gpg >/dev/null; curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg; echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list; apt-get update -qq; apt-get install -y -qq wazuh-agent=4.14.8-1 >/dev/null; apt-mark hold wazuh-agent >/dev/null; systemctl daemon-reload; systemctl enable --now wazuh-agent >/dev/null 2>&1; echo "agent: $(systemctl is-active wazuh-agent)"' || echo "!! $id FAILED"; done
```

3. Verify on `gullion` (agents sit at `Pending` for up to a minute — W4), then remove the secret:

```bash
sudo /var/ossec/bin/agent_control -l | grep -c Active
sudo /var/ossec/bin/agent_control -l | grep -vE 'Active|^$|List of|^ *ID: 000'   # must print nothing
shred -u /root/.wazuh-enrol                                                       # on every node used
```

The password is briefly visible in the CT's process environment during install — accepted on single-admin hosts. If an agent loops `Invalid password`, the dashboard password was used instead of the enrolment password (W5): rewrite the agent's `/var/ossec/etc/authd.pass` and restart; no reinstall.

## 4. Agent groups and centralised config

| Group | Members | Purpose |
|---|---|---|
| `default` | all | Stock agent config (12 h scheduled FIM on `/etc`, `/usr/bin`, `/usr/sbin`; SCA; syscollector; vulnerability inventory) |
| `proxmox-nodes` | 001–003 | Control-plane FIM, whodata, auditd log shipping |

Agents keep `default` and gain additional groups (multi-group). Created with:

```bash
sudo /var/ossec/bin/agent_groups -a -g proxmox-nodes -q
for i in 001 002 003; do sudo /var/ossec/bin/agent_groups -a -i $i -g proxmox-nodes -q; done
```

### 4.1 `/var/ossec/etc/shared/proxmox-nodes/agent.conf` (wazuh:wazuh 660)

```xml
<agent_config>
  <syscheck>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/network,/etc/kernel,/etc/default,/etc/modprobe.d,/etc/sysctl.d,/etc/cron.d</directories>
    <directories whodata="yes" check_all="yes" report_changes="yes">/etc/ssh</directories>
    <nodiff type="sregex">^/etc/ssh/ssh_host_.*_key$</nodiff>
    <directories realtime="yes" check_all="yes" report_changes="no">/var/spool/cron/crontabs</directories>
    <directories check_all="yes" report_changes="no">/etc/pve</directories>
    <ignore type="sregex">^/etc/pve/\.</ignore>
    <ignore type="sregex">/lrm_status|/manager_status|^/etc/pve/priv/lock</ignore>
  </syscheck>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</agent_config>
```

Backup: `agent.conf.bak-20261012`. Always validate before agents pull it: `sudo /var/ossec/bin/verify-agent-conf -f <file>`. Agents fetch the merged config on keepalive and auto-restart (1–3 min); force with `agent_control -R -u <id>`.

**Design notes:**
- `/etc/pve` is pmxcfs (FUSE): inotify misses changes made on other nodes → **scheduled** scan only (default 43200 s). Dotfiles (`.members`, `.rrd`, `.vmlist`, `.clusterlog`), `lrm_status`, `manager_status`, `priv/lock` churn constantly → ignored. **Never `report_changes`** — `priv/` holds the authkey and keys (W10).
- One `/etc/pve` change produces three events (one per node). Accepted for resilience; level 5–7, no email.
- `report_changes` stores diffs on the manager: never on key material — `nodiff` for SSH host private keys, off for crontabs.
- `whodata` on `/etc/ssh` attributes changes to user/process/session. Wazuh writes `/etc/audit/plugins.d/af_wazuh.conf`, restarts auditd and adds a `wazuh_fim` audit rule itself. Timestamp-only changes (`touch`) produce **no** whodata alert (W8).

### 4.2 Verification on a node

```bash
grep -c '<directories' /var/ossec/etc/shared/merged.mg
grep -E '\((6003|6012|6019)\)' /var/ossec/logs/ossec.log | tail -n 10   # 6003 per path; 6012 realtime started; 6019 whodata started
auditctl -l | grep -c wazuh_fim                                          # 1
```

End-to-end FIM test (real create/delete, name sshd never reads):

```bash
# node
echo '# wazuh whodata test - safe to delete' > /etc/ssh/wazuh-whodata-test && sleep 5 && rm /etc/ssh/wazuh-whodata-test
# gullion — expect 554 then 553 with "(Audit) User name: root", "Process name: /usr/bin/bash" / "/usr/bin/rm"
sleep 15; sudo grep -A30 "wazuh-whodata-test" /var/ossec/logs/alerts/alerts.log | grep -E '^Rule:|^File|\(pve\)|User name|Process name' | head -n 14
```

## 5. auditd on the nodes

`auditd` installed on pve/pve2/pve3; rules in `/etc/audit/rules.d/50-pve.rules` (640 root), loaded with `augenrules --load`:

```
## Homelab PVE audit rules (Wazuh SCA, 12 Oct 2026). Minimal by design: no blanket execve.
## auid!=unset excludes daemons (chronyd, systemd) so time and module noise only shows human sessions.
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/gshadow -p wa -k identity
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F auid!=unset -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/network/ -p wa -k network
-w /etc/hosts    -p wa -k network
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid!=unset -k modules
-w /etc/ssh/sshd_config   -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/cron.d/           -p wa -k cron
-w /var/spool/cron/       -p wa -k cron
```

- **No `execve`:** root cron jobs carry `auid 0`; the Ultimate Updater would flood the manager twice daily.
- **No `-e 2`:** immutable rules need a reboot to change — wrong trade-off while tuning.
- "Old style watch rules are slower" on load is advisory only.
- Health: `auditctl -s | grep -E '^(enabled|lost|backlog_limit)'` → `enabled 1`, `lost 0`, 8192. Test: `touch /etc/hosts; ausearch -k network -ts recent -i | tail -n 2`.

Wazuh decodes `audit.log` with the stock 80700-series rules — no custom decoders needed.

## 6. Email alerting

Wazuh's `wazuh-maild` cannot authenticate to SMTP, and the all-in-one ships `email_notification no` with `example.wazuh.com` placeholders (W7). Solution: **Postfix null-client on `gullion`** relaying to the mail provider.

### 6.1 Postfix

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postfix libsasl2-modules bsd-mailx
sudo postconf -e 'inet_interfaces = loopback-only' 'mydestination =' 'relayhost = [smtp.example.net]:465' \
  'smtp_tls_wrappermode = yes' 'smtp_tls_security_level = encrypt' 'smtp_sasl_auth_enable = yes' \
  'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd' 'smtp_sasl_security_options = noanonymous'
sudo install -m 600 -o root -g root /dev/null /etc/postfix/sasl_passwd && sudo nano /etc/postfix/sasl_passwd
#   [smtp.example.net]:465 wazuh@example.com:<APP_PASSWORD>     (dedicated app password; never pasted elsewhere)
sudo postmap /etc/postfix/sasl_passwd && sudo chmod 600 /etc/postfix/sasl_passwd.db && sudo systemctl restart postfix
ss -ltnp | grep ':25 '        # 127.0.0.1:25 and [::1]:25 only
echo "relay test $(date -Is)" | mail -r wazuh@example.com -s "gullion relay test" alerts@example.com
```

`email_from` / envelope sender must be the authenticated identity or the mail provider rejects it. `restart` (not reload) is required after changing `inet_interfaces`.

### 6.2 `ossec.conf` (`<global>`)

| Setting | Value |
|---|---|
| `email_notification` | `yes` |
| `smtp_server` | `localhost` |
| `email_from` | `wazuh@example.com` |
| `email_to` | `alerts@example.com` |
| `email_alert_level` | `12` |
| `email_maxperhour` | default 12 (excess batched into a digest) |

Backup `ossec.conf.bak-20261012` (`cp -p` keeps `root:wazuh 640`). Apply with `systemctl restart wazuh-manager`.

**What emails:** any alert at level ≥12 (12 high-importance event, 13 unusual error, 14 high-importance security event, 15 severe attack — e.g. 5108 OOM) plus any rule tagged `alert_by_email`. **What does not:** SSH brute force (5712, L10), repeated auth failures (L10), FIM changes (L5–7), package installs (L7), sudo (L3), SCA, most vulnerability findings.

**End-to-end test** (manager reads its own journal; matches 5108):

```bash
logger -p kern.crit -t kernel "Memory cgroup out of memory: Killed process 99999 (wazuh-mail-test) total-vm:0kB, anon-rss:0kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:0kB oom_score_adj:0"
```

Expect "Wazuh notification – (gullion) … Alert level 12" at `alerts@`. If not: `grep -A3 wazuh-mail-test /var/ossec/logs/alerts/alerts.log` (did the rule fire?) then `tail /var/log/mail.log`. The test leaves a fake 5108 in the dashboard — ignore it.

## 7. SCA (CIS benchmarks)

Policies: `cis_debian13` (nodes, Debian 13 CTs), `cis_debian12` (CT 101, CT 141 class), `sca_distro_independent_linux` (`fedhome`). Baseline 12 Oct 2026: ~93–105 failed of ~207 checks per host, near-identical across hosts.

| Outcome | Checks |
|---|---|
| **Fixed (nodes)** | sshd hardening (§8); auditd + rules (§5); `chmod og-rwx /etc/crontab /etc/cron.{hourly,daily,weekly,monthly} /etc/cron.d`; `apt-get purge telnet inetutils-telnet` |
| **Fixed (`eagle`)** | sshd disabled entirely (admin via Raspberry Pi Connect) |
| **Accepted by design** | Separate partitions + mount options (33010–33035: ZFS datasets/LXC rootfs) · ufw/nftables/iptables policy (33126–33151: `pve-firewall` owns filtering) · AIDE (Wazuh FIM) · PAM ageing/pwquality/faillock/history (key-only root admin) · sudo (none) · journal-remote/rsyslog (Wazuh collects journald) · bootloader password, banners · `PermitRootLogin`/`DisableForwarding` on nodes (clustering, secure migration) · NFS/rpcbind on pve and pve3 |
| **False positives (verified live)** | 33300 shadowed passwords · 33204 `nullok` · 33211 hashing (YESCRYPT) · 33039 AppArmor installed (4.1.1-pmx1, enabled) · 33096 chrony as `_chrony` (W11) |

Verification one-liner used on pve:

```bash
awk -F: '$2!="x"{print "NOSHADOW:",$1}' /etc/passwd; sudo awk -F: '($2==""){print "EMPTYPW:",$1}' /etc/shadow; grep -rn nullok /etc/pam.d/ | head -n 3; grep -E '^ENCRYPT_METHOD' /etc/login.defs; dpkg -l apparmor | tail -n1; aa-status --enabled && echo AA-ON; ps -o user= -C chronyd
```

## 8. Node sshd hardening (applied with SCA)

`/etc/ssh/sshd_config.d/50-hardening.conf` on pve/pve2/pve3 (drop-ins are included first; first value wins):

```
# CIS-aligned hardening (Wazuh SCA, 12 Oct 2026). PVE clustering needs root key SSH + forwarding.
PermitRootLogin prohibit-password
MaxAuthTries 4
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 3
MaxStartups 10:30:60
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
```

Apply per node with `sshd -t && systemctl reload ssh` (existing sessions survive), then prove cluster SSH from a peer in a **new** connection: `ssh -o BatchMode=yes root@<node> 'hostname; pvecm status | grep -E "^Quorate"'`. FIM logged each drop-in as rule 554 — a live test of §4.

## 9. Vulnerability detection

`<vulnerability-detection>` enabled, `index-status yes`, feed update 60 m. Findings in Dashboard → Vulnerability Detection → Inventory.

Triage method (12 Oct 2026 export: 857 rows, 52 Critical, 805 High):
1. Discard as noise: `vim-tiny`/`vim-common` (320 rows), CVEs Debian marks *no fix available*.
2. Proxmox-repo packages (`proxmox-kernel`, `pve-qemu-kvm`, `pve-*`) are poorly matched by the feed — absence of findings is **not** a clean bill; patch via the updater and Proxmox security announcements.
3. Act on **fixed version available but not installed**: check with `apt list --upgradable` on the host. On 12 Oct this found `oriel` 12 pending `oldstable-security` updates (applied) and `eagle` 141 pending incl. fixes for all 27 of its criticals (applied; `eagle` now has `unattended-upgrades` — it sits outside the Ultimate Updater).

## 10. Operations

### 10.1 Routine checks

```bash
sudo /var/ossec/bin/agent_control -l | grep -c Active          # expect 30
sudo /var/ossec/bin/agent_control -l | grep -vE 'Active|^$|List of|^ *ID: 000'
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat postfix
```

### 10.2 Upgrades (deliberate only)

Manager stack first (`apt-mark unhold` → upgrade wazuh-indexer, wazuh-manager, wazuh-dashboard, filebeat per the Wazuh upgrade guide → re-hold), confirm healthy, then agents to the **same** version (re-run the enrolment loop's install/hold section per CT, or `apt-mark unhold wazuh-agent && apt-get install wazuh-agent=<ver> && apt-mark hold wazuh-agent`). `fedhome`: temporarily enable the repo. Never let the Ultimate Updater or `unattended-upgrades` touch Wazuh (`eagle` blacklists `wazuh-agent`).

### 10.3 Removing an agent

`sudo /var/ossec/bin/manage_agents -r <id>` on the manager, then `apt-get purge wazuh-agent` on the host. Record the change in your inventory.

### 10.4 Tuning backlog (~18 Oct 2026)

- Top rules by count; `local_rules.xml` overrides for Ultimate Updater apt/dpkg noise (03:00/10:00 on every CT) and updater-snapshot `qemu-server/*.conf` / `lxc/*.conf` FIM churn.
- `/etc/pve` scan frequency (consider 3600 s).
- `alert_by_email` for FIM on `/etc/ssh` and `/etc/network`; consider whodata on `/etc/network`.
- Consider `email_alert_level` 10 (adds brute force / auth-failure bursts).
- Re-assess CT 122 enrolment (~19 Oct); optionally rotate dashboard `admin` password (Wazuh password tool).

### 10.5 Tuning applied (18 Oct 2026)

Pre-tuning baseline: ~180k alerts/week, no level ≥12 after the Plex fix. Top sources: SSH session/auth (5501/5502/5715, ~136k — ~75 %), rootcheck 510 (17.7k), AppArmor 80730/52002 (7.3k), web 400s on the Nextcloud app (2.2k), FIM 550 (2k).

**Review query** (run as root — a `sudo zcat …/*` glob expands in the user's shell and silently reads only today, W12):

```bash
sudo bash -c 'zcat -f /var/ossec/logs/alerts/2026/*/ossec-alerts-*.json.gz /var/ossec/logs/alerts/alerts.json' | jq -r 'select(.timestamp > (now-604800|strftime("%Y-%m-%dT%H:%M:%S"))) | "\(.rule.level)\t\(.rule.id)\t\(.rule.description)"' | sort | uniq -c | sort -rn | head -n 30
```

**`default` group `agent.conf`** :

```xml
<agent_config>
  <rootcheck>
    <ignore type="sregex">^/dev/\.lxc</ignore>
  </rootcheck>
  <syscheck>
    <ignore type="sregex">^/etc/pihole/gravity</ignore>
    <ignore type="sregex">^/etc/lvm/archive/</ignore>
    <ignore type="sregex">^/etc/ultimate-updater/</ignore>
  </syscheck>
</agent_config>
```

**`local_rules.xml`** additions:

| Rule | Parent | Match | Level | Why |
|---|---|---|---|---|
| 100110 | 80710 | `audit.dev` `^(tap\|veth\|fwpr\|fwln\|fwbr)` | 0 | Guest NICs join bridges in promiscuous mode on every guest start |
| 100120 | 5715 | `srcip 10.0.1.0/24`, `user ^root$` | 0 | pvesr / syncoid / dump-mirror over the fabric |
| 100121–100123 | 5715 | `srcip` = pve2 / pve / pve3 mgmt IPs, `user ^root$` | 0 | Updater fan-out and replication over mgmt |

PAM 5501/5502 deliberately kept (no source field — suppressing would hide real root sessions). Static fields use `<user>`/`<srcip>`, not `<field>` (W13). Validate with `wazuh-analysisd -t && systemctl restart wazuh-manager`.

**Findings acted on outside Wazuh:** an unrestricted NAS service key (CT 112 photo sync) restricted to read-only rrsync from a static address; a pre-tunnel nginx + expired certbot certificate and a redundant rsyslog (the AppArmor denials) disabled on the Ubuntu Mealie CT; certificate-pull keys on the ACME CT confirmed already restricted. Internet scanner 400s are to be blocked at the Cloudflare WAF rather than suppressed.

**Kept on purpose:** dpkg 2901/2902/2904 (patch history), FIM `/usr/bin` and `/etc/pve/.../lxc/` changes, firmware-overlay FIM on the monitoring Pi, netstat 533 on the workstation (level 7, no email).

## 11. Incident: first high alerts (12 Oct 2026)

Two rule 5108 (level 12, "System running out of memory") alerts from pve3 were cgroup OOM kills inside CT 122 (UID 100998 = container `plex`). Kill times repeated every ~2h22m (04:19, 06:41, 09:04 local) on consecutive days → a re-queued job. `Plex Media Server.log` showed `LoudnessJobManager: job for item 12910 failed (-9)`; a read-only `Plex SQLite` query mapped item 12910 to a 59 GB multi-language TrueHD Atmos UHD REMUX of *Tron: Legacy* whose loudness analysis grew to the 4 GiB cgroup. The duplicate REMUX was deleted (a 10.9 GB AV1 version kept). Rule 5108 stays enabled — it found a real fault on day one.

## 12. Gotchas

| # | Lesson |
|---|---|
| W1 | Pin agents to the manager version and hold both sides |
| W2 | Debian 13: dearmor the repo key (`gpg --dearmor`) |
| W3 | Installer prints `https://:443` — cosmetic |
| W4 | New agents show `Pending` for up to a minute |
| W5 | `Invalid password` loop = wrong secret; fix `authd.pass` in place |
| W6 | Any `W:` from `apt-get update` = broken update path |
| W7 | Email needs a local authenticated relay |
| W8 | Whodata ignores timestamp-only changes — test with create/delete |
| W9 | Balloon-0 VM looks 100 % used in PVE — check `free -m` inside |
| W10 | `/etc/pve`: scheduled, no diffs, ignore churn files |
| W11 | Verify surprising SCA failures live before acting |
| W12 | Expand root-only log globs as root (`sudo bash -c`) |
| W13 | Static fields need `<user>`/`<srcip>`; always `analysisd -t` before restart |

---

*End of document (v1.1, 18 October 2026). Maintain via PR/commit; keep aligned with the internal counterpart.*
