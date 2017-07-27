#!/bin/bash

#4.1
#Set User/Group Owner on /boot/grub2/grub.cfg
#set the owner & group to the root user
chown root:root /boot/grub2/grub.cfg

#4.2
#Set Permissions on /boot/grub2/grub.cfg
#set permission to read+write for root only
chmod og-rwx /boot/grub2/grub.cfg

#4.3
#Set Boot Loader Password
#set boot loader pw for anyone rebooting the system
touch test1.pwd
echo "password" >> test1.pwd
echo "password" >> test1.pwd
grub2-mkpasswd-pbkdf2 < test1.pwd > test.md5
grub2-mkconfig -o /boot/grub2/grub.cfg

#5.1
#Restrict Core Dumps
#prevent users from overriding the soft variables
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

#5.2
#Enable Randomized Virtual Memory Region Placement
#set the system flag to force randomized virtual memory region placement
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

#6.1.1
#Install the rsyslogpackage
yum install rsyslog
systemctl enable rsyslog
systemctl start rsyslog

#6.1.2
#Activate the rsyslogService
#ensure rsyslog service is turned on
systemctl enable rsyslog

#6.1.3
#Configure /etc/rsyslog.conf
#ensure appropriate logging is set according to environment
sed -i 's/dev/var/g' /etc/rsyslog.conf
sed -i 's/console/log\/kern.log/g' /etc/rsyslog.conf

#6.1.4
#Create and Set Permissions on rsyslogLog Files
#ensure that log files exist & correct permissions are set
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
#Configure rsyslogto Send Logs to a Remote Log Host
echo " *.* @@localhost" >> /etc/rsyslog.conf
pkill -HUP rsyslogd

#6.1.6
#Accept Remote rsyslogMessages Only onDesignated Log Hosts
sed -i 's/#$ModLoad imtcp/$ModLoad imtcp.so/g' /etc/rsyslog.conf
sed -i 's/#$InputTCPServerRun 514/$InputTCPServerRun 514/g' /etc/rsyslog.conf
pkill -HUP rsyslogd

#6.2.1.1 Configure Audit Log Storage Size
sed -i '/max_log_file/s/= .*/= 5/' /etc/audit/auditd.conf

#6.2.1.2 Keep All Auditing Information (add 'max_log...' into this file)
sed -i '/max_log_file_action/s/= .*/= keep_logs/' /etc/audit/auditd.conf

#6.2.1.3 Disable System on Audit Log Full (add following lines into this file)
sed -i '/space_left_action/s/= .*/= email/' /etc/audit/auditd.conf
sed -i '/action_mail_acct/s/= .*/= root/' /etc/audit/auditd.conf
sed -i '/admin_space_left_action/s/= .*/= halt/' /etc/audit/auditd.conf

#6.2.1.4 Enable auditdService (allows admin to determine if unauthorized access to their system is occurring.)
systemctl enable auditd

#6.2.1.5 Enable Auditing for Processes That Start Prior to auditd
#(Audit events need to be captured on processes that start up prior to auditd, so that potential malicious activity cannot go undetected.)
sed -i 's/crashkernel=auto rhgb quiet/audit=1/g' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

#6.2.1.6 Record Events That Modify Date and Time Information
#(Unexpected changes in system date and/or time could be a sign of malicious activity on the system.)
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

#6.2.1.7 Record Events That Modify User/Group Information
#(Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts.)
echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
pkill -P 1 -HUP auditd

#6.2.1.8 Record Events That Modify the System's Network Environment
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
pkill -P 1 -HUP auditd

#6.2.1.9 Record Events That Modify the System's Mandatory Access Controls
#(indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system.)
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
pkill -P 1 -HUP auditd

#6.2.1.10 Collect Login and Logout Events
#(Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins)
echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
echo "-w /var/log/tallylog -p wa -k logins" >>  /etc/audit/audit.rules
pkill -P 1 -HUP auditd

#6.2.1.11 Collect session initiation information
#Add the following lines to /etc/audit/audit.rules file
echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/audit.rules
echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/audit.rules
#Execute following command to restart auditd
pkill -HUP -P 1 auditd

#6.2.1.12 Collect discretionary access control permission modification events
#Add the following lines to /etc/audit/audit.rules file
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
#Execute the following command to restart auditd
pkill -HUP -P 1 auditd

#6.2.1.13 Collect unsuccessful unauthorized access attempts to files
#Add the following lines to /etc/audit/audit.rules file
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules

#Execute following command to restart auditd
pkill -HUP -P 1 auditd

#6.2.1.14 Collect use of privileged commands
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path="$1" -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules

#6.2.1.15 Collect successful file system mounts
#Add the following lines to /etc/audit/audit.rules file
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
#Execute the following command to restart auditd
pkill -HUP -P 1 auditd

#6.2.1.16 Collect file deletion events by user
#Add the following lines to /etc/audit/audit.rules file
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
#Execute the following command to restart auditd
pkill -HUP -P 1 auditd

#6.2.1.17 Collect changes to system administration scope
#Add the following lines to /etc/audit/audit.rules file
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
#Execute the following command to restart auditd
pkill -HUP -P 1 auditd

#6.2.1.18 Collect system administrator actions (syslog)
#Add the following lines to /etc/audit/audit.rules file
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
#Execute the following command to restart auditd
pkill -HUP -P 1 auditd

#6.2.1.19 Collect kernel module loading and unloading
#Add the following lines to /etc/audit/audit.rules file
echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules

#6.2.1.20 Make the audit configuration immutable
#Add the following lines to /etc/audit/audit.rules file
echo "-e 2" >> /etc/audit/audit.rules

#6.2.1.21 Configure logrotate
#Edit the /etc/logrotate.d/syslog file to include appropriate system logs
echo "/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron {" >> /etc/logrotate.d/syslog




