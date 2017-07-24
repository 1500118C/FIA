#!/bin/bash

#4.1
chown root:root /boot/grub2/grub.cfg

#4.2
chmod og-rwx /boot/grub2/grub.cfg

#4.3
touch test.pwd
grub2-mkpasswd-pbkdf2 < test.pwd > test.md5
grub2-mkconfig -o /boot/grub2/grub.cfg

#5.1
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

#5.2
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

#6.1.1
yum install rsyslog
systemctl enable rsyslog
systemctl start rsyslog

#6.1.2
systemctl enable rsyslog

#6.1.3
sed -i 's/dev/var/g' /etc/rsyslog.conf
sed -i 's/console/log\/kern.log/g' /etc/rsyslog.conf

#6.1.4
touch /var/log/kern.log
chown root:root /var/log/kern.log
chmod og-rwx /var/log/kern.log
touch /var/log/messages
chown root:root /var/log/messages
chmod og-rwx /var/log/messages
touch /var/log/secure
chown root:root /var/log/secure
chmod og-rwx /var/log/secure
touch /var/log/maillog
chown root:root /var/log/maillog
chmod og-rwx /var/log/maillog
touch /var/log/cron
chown root:root /var/log/cron
chmod og-rwx /var/log/cron
touch /var/log/spooler
chown root:root /var/log/spooler
chmod og-rwx /var/log/spooler
touch /var/log/boot.log
chown root:root /var/log/boot.log
chmod og-rwx /var/log/boot.log

#6.1.5
echo " *.* @@localhost" >> /etc/rsyslog.conf
pkill -HUP rsyslogd

#6.1.6
pkill -HUP rsyslogd

#6.2.1.1
sed -i '/max_log_file/s/= .*/= 5/' /etc/audit/auditd.conf

#6.2.1.2
sed -i '/max_log_file_action/s/= .*/= keep_logs/' /etc/audit/auditd.conf

#6.2.1.3
sed -i '/space_left_action/s/= .*/= email/' /etc/audit/auditd.conf
sed -i '/action_mail_acct/s/= .*/= root/' /etc/audit/auditd.conf
sed -i '/admin_space_left_action/s/= .*/= halt/' /etc/audit/auditd.conf

#6.2.1.4
systemctl enable auditd

#6.2.1.5
sed -i 's/crashkernel=auto rhgb quiet/audit=1/g' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

#6.2.1.6
echo "-a always, exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules

echo "-a always, exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >>/etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules

pkill -P 1 -HUP auditd


#6.2.1.7
echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
pkill -P 1 -HUP auditd

#6.2.1.8
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
pkill -P 1 -HUP auditd

#6.2.1.9
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
pkill -P 1 -HUP auditd

#6.2.1.10
echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
echo "-w /var/log/tallylog -p wa -k logins" >>  /etc/audit/audit.rules
pkill -P 1 -HUP auditd

#6.2.1.11
echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/audit.rules
echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/audit.rules
pkill -HUP -P 1 auditd

#6.2.1.12
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
pkill -HUP -P 1 auditd

#6.2.1.13
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules

pkill -HUP -P 1 auditd

#6.2.1.14

#6.2.1.15
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
pkill -HUP -P 1 auditd

#6.2.1.16
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
pkill -HUP -P 1 auditd

#6.2.1.17
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
pkill -HUP -P 1 auditd

#6.2.1.18
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
pkill -HUP -P 1 auditd

#6.2.1.19
echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules

#6.2.1.20
echo "-e 2" >> /etc/audit/audit.rules

#6.2.1.21
echo "/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron {" >> /etc/logrotate.d/syslog
