# Production-Ready Ubuntu Server Hardening (Ubuntu 26.04 LTS on VirtualBox)

I hardened a fresh Ubuntu Server 26.04 LTS virtual machine with 20 security controls across patching, account and password policy, SSH, network and kernel settings, mandatory access control, auditing, and file permissions. I then rebooted the server and verified that every control persisted. A Lynis audit of the finished server scored a hardening index of **66**. Along the way I diagnosed several real-world issues the lab instructions didn't anticipate, including a VM clock that drifted hours out of sync and a default config file that was missing the setting I was told to edit.

*ISC 3033 Operating Systems Security, The University of Texas at San Antonio, Fall 2026 (Lab 03).*

---

## Environment

| Item | Details |
|---|---|
| Hypervisor | Oracle VirtualBox (NAT networking, host port forwarding for SSH) |
| Guest OS | Ubuntu Server 26.04.1 LTS, kernel 7.0, headless (CLI only) |
| VM size | 3 vCPUs, 4 GB RAM, 50 GB disk |
| Access | SSH from Windows PowerShell with an Ed25519 key |
| Tools | apt, unattended-upgrades, chrony, libpam-pwquality, chage, OpenSSH, Fail2Ban, UFW, sysctl, ss, AppArmor, auditd, Lynis |
| Safety net | VirtualBox snapshot taken before any changes |

---

## What I built or hardened

| # | Control or feature | Threat or purpose | Verified by |
|---|---|---|---|
| 1 | Full system patch | Known, already-published vulnerabilities | `apt list --upgradable` shows nothing left |
| 2 | Automatic security updates | Window between patch release and install | `systemctl status unattended-upgrades`, `20auto-upgrades` |
| 3 | Remove unused packages | Attack surface from software nobody uses | `apt autoremove --purge`, package count (789) |
| 4 | Time synchronization (chrony) | Wrong log timestamps undermine investigations | `timedatectl status`: synchronized yes |
| 5 | User account audit | Hidden UID 0 accounts, empty passwords, unexpected logins | Four `awk`/`getent` checks |
| 6 | Password complexity (pwquality) | Weak, guessable passwords | Weak password rejected by `passwd` |
| 7 | Password aging (90/7/14) | Long-lived compromised passwords; instant reuse | `chage -l` |
| 8 | Restrictive umask + legal banner | New files readable by every account; legal notice for prosecution | `umask`, `/etc/login.defs`, `/etc/issue.net` |
| 9 | Ed25519 SSH key pair | Password theft and guessing | Key login with no password prompt |
| 10 | SSH server hardening | Direct root login, brute force, tunneling, idle sessions | `sshd -t`, new login works |
| 11 | Disable SSH passwords | Password brute force and credential stuffing | Forced password login: `Permission denied (publickey).` |
| 12 | Fail2Ban SSH jail | Repeated failed logins from one source | `fail2ban-client status sshd` |
| 13 | UFW firewall (default deny in) | Exposure of any service except SSH | `ufw status verbose` |
| 14 | Kernel network hardening + ASLR | IP spoofing, SYN floods, ICMP redirects, memory-corruption exploits | `sysctl` checks |
| 15 | Listening-service audit | Unknown services reachable from the network | `ss -tulpn`, running services list |
| 16 | AppArmor enforcement | A compromised program accessing files outside its profile | `aa-status`: 105 profiles enforcing |
| 17 | auditd file watches | Undetected changes to identity, sudo, and SSH config | `auditctl -l` (5 rules) |
| 18 | Sticky `/tmp` + sensitive file permissions | Deleting others' temp files; reading password hashes | `ls -ld /tmp`, `ls -l /etc/shadow ...` |
| 19 | Lynis security audit | Independent check and next-step recommendations | Hardening index 66, 260 tests |
| 20 | Reboot and verify | Settings that only last until restart | Six verification commands after reboot |

---

## Key commands

### Part 1: Patching and attack surface

```bash
sudo apt update && sudo apt upgrade -y
sudo apt update && apt list --upgradable

# Packages "kept back" by Ubuntu phased updates can be upgraded explicitly:
sudo apt install --only-upgrade <package-1> <package-2> -y

sudo apt install unattended-upgrades -y
sudo systemctl enable --now unattended-upgrades
cat /etc/apt/apt.conf.d/20auto-upgrades

sudo apt autoremove --purge -y
sudo apt autoclean
dpkg -l | grep -c '^ii'

sudo timedatectl set-ntp true
timedatectl status
```

### Part 2: Users, passwords, and access control

```bash
awk -F: '($3 == 0) {print $1}' /etc/passwd            # accounts with UID 0 (root powers)
sudo awk -F: '($2 == "") {print $1}' /etc/shadow      # accounts with empty passwords
getent group sudo                                     # who has admin rights
awk -F: '($7 !~ /(nologin|false)$/) {print $1": "$7}' /etc/passwd   # accounts that can log in
```

`/etc/security/pwquality.conf` (negative credit values mean "require at least this many"):

```ini
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
```

```bash
sudo chage -M 90 -m 7 -W 14 $USER
sudo chage -l $USER

# Ubuntu 26.04's login.defs had no UMASK line, so I appended one.
# The -a matters: without it, tee overwrites the whole file.
sudo cp /etc/login.defs /etc/login.defs.bak
echo "UMASK 027" | sudo tee -a /etc/login.defs
grep -n "^UMASK" /etc/login.defs
sudo nano /etc/issue.net    # legal warning banner
```

### Part 3: SSH hardening

```powershell
# On the Windows client (one line). Add -p <port> if you connect through port forwarding.
ssh-keygen -t ed25519 -C "lab03-key"
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh <user>@<server-ip> "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

`/etc/ssh/sshd_config.d/99-hardening.conf`:

```text
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/issue.net
PasswordAuthentication no
KbdInteractiveAuthentication no
```

```bash
sudo sshd -t                        # prints nothing if the config is valid; fix errors BEFORE restarting
sudo systemctl restart ssh
sudo sshd -T | grep -E "passwordauthentication|kbdinteractiveauthentication"   # effective settings
```

```powershell
# Test from a NEW window while the old session stays open. This should FAIL:
ssh -o PubkeyAuthentication=no <user>@<server-ip>
```

`/etc/fail2ban/jail.local`:

```ini
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd

[sshd]
enabled = true
```

```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

### Part 4: Network and firewall

```bash
sudo ufw allow OpenSSH              # MUST come before enable, or you cut off your own session
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
sudo ufw status verbose
```

`/etc/sysctl.d/99-hardening.conf`:

```ini
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.ip_forward = 0
kernel.randomize_va_space = 2
```

```bash
sudo sysctl --system
sysctl net.ipv4.tcp_syncookies kernel.randomize_va_space
sudo ss -tulpn
systemctl list-units --type=service --state=running --no-pager
```

### Part 5: Monitoring, auditing, and verification

```bash
sudo apt install apparmor-utils -y          # no space before -utils (see Troubleshooting)
sudo aa-status
systemctl is-enabled apparmor && systemctl is-active apparmor

sudo apt install auditd audispd-plugins -y
sudo systemctl enable --now auditd
```

`/etc/audit/rules.d/hardening.rules`:

```text
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/ssh/sshd_config -p wa -k sshconfig
-w /var/log/auth.log -p wa -k authlog
```

```bash
sudo augenrules --load
sudo auditctl -l
sudo ausearch -k identity -i

ls -ld /tmp
sudo chmod 600 /etc/shadow
sudo chmod 644 /etc/passwd
sudo chmod 440 /etc/sudoers
ls -l /etc/shadow /etc/passwd /etc/sudoers

sudo apt install lynis -y
sudo lynis audit system --quick
sudo grep 'hardening_index' /var/log/lynis-report.dat

# After reboot:
sudo ufw status verbose
sudo fail2ban-client status sshd
sudo aa-status --enabled && echo 'AppArmor OK'
systemctl is-active auditd unattended-upgrades
sysctl kernel.randomize_va_space net.ipv4.tcp_syncookies
umask
```

---

## Results

- System fully patched, with automatic security updates enabled
- Password policy enforced: 14-character minimum with all four character types, 90-day maximum age, 7-day minimum, 14-day warning
- SSH accepts **keys only**; root login, X11 forwarding, and TCP forwarding are disabled
- Fail2Ban SSH jail active; UFW denies all inbound traffic except SSH
- Kernel network hardening applied and full ASLR (`randomize_va_space = 2`) confirmed
- Only four listening ports, all identified: SSH (22), local DNS (53), DHCP client (68), chrony command port (323, localhost only)
- AppArmor: 105 profiles enforcing, 2 in complain mode
- auditd watching identity, sudoers, SSH config, and auth log changes
- Lynis hardening index: **66** (260 tests)
- **Every control survived a full reboot**

---

## Troubleshooting and lessons learned

| Problem | Cause | Fix |
|---|---|---|
| Two packages stayed upgradable after `apt upgrade` | Ubuntu **phased updates** release new versions to a growing percentage of machines; mine wasn't selected yet | `sudo apt install --only-upgrade <packages>`; checked the phase with `apt policy <package>` |
| `System clock synchronized: no` even though NTP was active | I saved the VM's state and slept the host; the VM clock froze and resumed hours behind. chrony's default `makestep 1 3` only allows a clock step in its first 3 updates after starting | `sudo chronyc makestep`, changed to `makestep 1 -1`, and full reboots; diagnosed with `chronyc sources` and `chronyc tracking` (huge RMS offset, "Not synchronised") |
| My first sync diagnosis was wrong | `chronyc sources` showed a selected `^*` source, but `chronyc tracking` showed chrony wasn't synced at that moment | Checked a second source of truth before concluding |
| Ctrl+W search for `UMASK` in `login.defs` found nothing | Ubuntu 26.04's shipped `login.defs` had **no UMASK line**; `pam_umask` falls back to its default | Confirmed `pam_umask` was enabled, backed up the file, appended `UMASK 027` with `tee -a` |
| `umask` showed 0007, not the 0027 the lab expected | `USERGROUPS_ENAB yes` + username matching the primary group name → `pam_umask` copies the owner digit into the group digit | Documented as expected behavior; "others" still get no access |
| Password test said "shorter than 13 characters" with `minlen = 14` | I set `dcredit = 1`; a positive credit lets a digit **count as an extra character** instead of requiring one | Set `dcredit = -1`, retested |
| `passwd` refused to change my password again | My own Task 7 policy (`chage -m 7`) blocked a second change within 7 days | Temporarily `chage -m 0`, tested and canceled with Ctrl+C, restored `-m 7` |
| First key login failed | Forgot `-p <port>` for VirtualBox NAT port forwarding | Added the port to every SSH command |
| `apt install apparmor -utils` → error about release "ils" | The space split the name; apt read `-utils` as `-u -t ils` (target release "ils") | `sudo apt install apparmor-utils -y` |
| VM showed **Aborted** and Start was grayed out | VM process died while the host slept; a leftover VirtualBox process held the lock | Rebooted the host and started the VM normally (did **not** restore the pre-lab snapshot, which would have erased all the work) |

**Key takeaways**

- **"Running" isn't "working."** chrony was active and configured correctly, but the clock was still wrong. Verify the actual result, not the service status.
- **Never change login methods without a second open session.** I kept one SSH window open the whole time and tested every SSH change in a new window before trusting it.
- **Lab instructions drift from real systems.** On a current Ubuntu release, the UMASK line didn't exist and the umask came out as 0007. Understanding *why* mattered more than matching the expected output.
- **Order of operations is a security control.** Allowing OpenSSH before enabling UFW, and testing key login before disabling passwords, are what prevent lockouts.
- **Mitigation is not a fix.** ASLR makes the buffer overflow from my earlier lab unreliable to exploit, but the bug is still there; the real fix is bounds checking in the code.

---

## Skills demonstrated

- Linux server hardening against CIS-style controls on Ubuntu 26.04 LTS
- SSH public-key authentication and `sshd` hardening with drop-in config files
- Host firewall configuration (UFW) and brute-force protection (Fail2Ban)
- Kernel tuning with persistent `sysctl` settings, including ASLR
- PAM password policy (pwquality, password aging, `pam_umask`)
- Mandatory access control with AppArmor
- Security auditing with auditd and Lynis
- Network service auditing with `ss` (TCP vs. UDP socket states, localhost vs. network binding)
- Troubleshooting time synchronization with chrony in a virtualized environment
- Mapping controls to attacks: brute force, credential stuffing, SYN floods, IP spoofing, ICMP redirects, memory-corruption exploits, offline password-hash cracking, `/tmp` symlink attacks

---

## References

- [Ubuntu Server documentation: About apt upgrade and phased updates](https://documentation.ubuntu.com/server/explanation/software/about-apt-upgrade-and-phased-updates/)
- [Ubuntu Server documentation: Synchronize time using chrony](https://documentation.ubuntu.com/server/how-to/networking/serve-ntp-with-chrony/)
- [chrony documentation: chrony.conf (`makestep`, `cmdport`)](https://chrony-project.org/doc/latest/chrony.conf.html)
- [Ubuntu Server documentation: OpenSSH server](https://documentation.ubuntu.com/server/how-to/security/openssh-server/)
- [Linux kernel documentation: `/proc/sys/kernel/` (randomize_va_space)](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [Linux kernel documentation: `/proc/sys/fs/` (protected_symlinks)](https://docs.kernel.org/admin-guide/sysctl/fs.html)
- [RFC 4252: The Secure Shell (SSH) Authentication Protocol](https://www.rfc-editor.org/rfc/rfc4252)
- [RFC 8709: Ed25519 and Ed448 Public Key Algorithms for SSH](https://www.rfc-editor.org/rfc/rfc8709)
- [PCI Security Standards Council: PCI DSS v4.0.1 document library](https://www.pcisecuritystandards.org/document_library/)
- [NIST SP 800-53 Rev. 5: Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [CIS Benchmarks: Ubuntu Linux](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Lynis by CISOfy](https://cisofy.com/lynis/)
