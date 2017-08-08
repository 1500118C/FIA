#LAB 2 REMEDIATION
#4.1
#Set User/Group Owner on /boot/grub2/grub.cfg
#set the owner & group to the root user

printf "Checking if grub.cfg belongs to root: "

if stat -L -c "owner=%U group=%G" /boot/grub2/grub.cfg | grep "owner=root group=root" >/dev/null ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else
	chown root:root /boot/grub2/grub.cfg
fi


#4.2
#Set Permissions on /boot/grub2/grub.cfg
#set permission to read+write for root only

printf "Checking if grub.cfg file is set to read and write for root only: "

if stat -L -c "%a" /boot/grub2/grub.cfg | grep "00" >/dev/null ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else
	chmod og-rwx /boot/grub2/grub.cfg
fi

#4.3
#Set Boot Loader Password
#set boot loader pw for anyone rebooting the system

printf "Checking if boot loader password is set: \n"

grep "set superusers" /boot/grub2/grub.cfg
grep "password" /boot/grub2/grub.cfg

if grep "password" /boot/grub2/grub.cfg >/dev/null ; then
	 printf "\e[32mNo remediation needed\e[0m\n"
else
	touch test1.pwd
	echo "password\npassword\n" >> test1.pwd
	grub2-mkpasswd-pbkdf2 < test1.pwd > test.md5
	grub2-mkconfig -o /boot/grub2/grub.cfg
fi

#5.1
#Restrict Core Dumps
#prevent users from overriding the soft variables

printf "Checking if core dumps are restricted: \n"

if grep "hard" /etc/security/limits.conf > /dev/null ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else
	echo "* hard core 0" >> /etc/security/limits.conf
	echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
fi

#5.2
#Enable Randomized Virtual Memory Region Placement
#set the system flag to force randomized virtual memory region placement

printf "Checking if virtual memory is randomized: "

if sysctl kernel.randomize_va_space >/dev/null ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else	
	echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
fi

#6.1.1
#Install the rsyslogpackage

printf "Checking if rsyslog package is installed: "

if rpm -q rsyslog | grep "rsyslog" >/dev/null ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else
	yum install rsyslog
	systemctl enable rsyslog
	systemctl start rsyslog
fi

#6.1.2
#Activate the rsyslogService
#ensure rsyslog service is turned on

printf "Checking if rsyslog is enabled: "

if systemctl is-enabled rsyslog | grep "enabled" >/dev/null ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else
	systemctl enable rsyslog
fi

#6.1.3
#Configure /etc/rsyslog.conf
#ensure appropriate logging is set according to environment

printf "Checking if appropriate logging is set: "

if (cat /etc/rsyslog.conf | grep "auth,user.* /var/log/messages" >/dev/null) || (cat /etc/rsyslog.conf | grep "kern.* /var/log/kern.log" >/dev/null) || (cat /etc/rsyslog.conf | grep "daemon.* /var/log/daemon.log" >/dev/null) || (cat /etc/rsyslog.conf | grep "syslog.* /var/log/daemon.log" >/dev/null) || (cat /etc/rsyslog.conf | grep "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log") ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else
	sed -i 's/dev/var/g' /etc/rsyslog.conf
	sed -i 's/console/log\/kern.log/g' /etc/rsyslog.conf
fi

#6.1.4
#Create and Set Permissions on rsyslogLog Files
#ensure that log files exist & correct permissions are set

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

printf "Checking if rsyslog sends logs to remote log host: "

if grep "^*.*[^|][^|]*@" /etc/rsyslog.conf *.* >/dev/null ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else
	echo "*.* @@localhost" >> /etc/rsyslog.conf
	pkill -HUP rsyslogd
	printf "\e[32mRsyslog sends logs to remote log host\e[0m\n"
fi

#6.1.6
#Accept Remote rsyslogMessages Only onDesignated Log Hosts

printf "Checking if rsyslog is listening for remote messages: "
printf "ModLoad imtcp.so: "

if grep '$ModLoad imtcp.so' /etc/rsyslog.conf >/dev/null ; then
	printf "\e[32mNo remediation needed\e[0m\n"
else

	sed -i 's/#$ModLoad imtcp/$ModLoad imtcp.so/g' /etc/rsyslog.conf
	sed -i 's/#$InputTCPServerRun 514/$InputTCPServerRun 514/g' /etc/rsyslog.conf
	pkill -HUP rsyslogd
fi

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

checkgrub=$(grep "linux" /boot/grub2/grub.cfg | grep "audit=1")
if [ -z "$checkgrub"  ]
then
        var="GRUB_CMDLINE_LINUX"
        sed -i /$var/d /etc/default/grub
        printf "\nGRUB_CMDLINE_LINUX=\"audit=1\"" >> /etc/default/grub
else
        echo "audit 1 is pr"
fi

grub2-mkconfig -o /boot/grub2/grub.cfg

#6.2.1.6 Record Events That Modify Date and Time Information
#(Unexpected changes in system date and/or time could be a sign of malicious activity on the system.)
checksystem=`uname -m | grep "64"`
checkmodifydatetimeadjtimex=`egrep 'adjtimex' /etc/audit/audit.rules`

if [ -z "$checksystem" ]
then
        echo "It is a 32-bit system."

        if [ -z "$checkmodifydatetimeadjtimex" ]
        then
                echo "Date & Time Modified Events - FAILED (Adjtimex is not configured)"
                echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules
                        echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
                echo "Adjtimex is now configured"

        else
echo "Date & Time Modified Events - PASSED (Adjtimex is configured)"
        fi

else
        echo "It is a 64-bit system."

        if [ -z "$checkmodifydatetimeadjtimex" ]
        then
                echo "Date & Time Modified Events - FAILED (Adjtimex is not configured)"
                        echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/audit.rules
                        echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
                echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules
                        echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
                echo "Adjtimex is now configured"
 else
                echo "Date & Time Modified Events - PASSED (Adjtimex is configured)"
        fi

fi

checkmodifydatetimesettime=`egrep 'settimeofday' /etc/audit/audit.rules`

if [ -z "$checksystem" ]
then

        if [ -z "$checkmodifydatetimesettime" ]
        then
                echo "Date & Time Modified Events - FAILED (Settimeofday is not configured)"
                echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
                        echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
                echo "Settimeofday is now configured"
else
                echo "Date & Time Modified Events - PASSED (Settimeofday is configured)"
        fi

else

        if [ -z "$checkmodifydatetimesettime" ]
        then
                echo "Date & Time Modified Events - FAILED (Settimeofday is not configured)"
                        echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
                        echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
                echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
                        echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
                echo "Settimeofday is now configured"
else
                echo "Date & Time Modified Events - PASSED (Settimeofday is configured)"
        fi

fi

checkmodifydatetimeclock=`egrep 'clock_settime' /etc/audit/audit.rules`

if [ -z "$checkmodifydatetimeclock" ]
then
        echo "Date & Time Modified Events - FAILED (Clock Settime is not configured)"
        echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules
                echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
        echo "Clock Settime is now configured"

else
        echo "Date & Time Modified Events - PASSED (Clock Settime is configured)"
fi

pkill -P 1 -HUP auditd


#6.2.1.7 Record Events That Modify User/Group Information
#(Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts.)
printf "Checking if events that modify user/group information are recorded:\n"
if (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/group -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/passwd -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/gshadow -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/shadow -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/security/opasswd -p wa -k identity" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
    echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
    pkill -P 1 -HUP auditd
    printf "\e[32mEvents that modify user/group information are recorded\e[0m\n"
fi

#6.2.1.8 Record Events That Modify the System's Network Environment
printf "Checking if events that modify the system's environment are recorded:\n"
if (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/issue -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/issue.net -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/hosts -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/sysconfig/network -p wa -k system-locale" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else
    echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
    echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
    pkill -P 1 -HUP auditd
    printf "\e[32mEvents that modify the system's environment are recorded\e[0m\n"
fi

#6.2.1.9 Record Events That Modify the System's Mandatory Access Controls
#(indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system.)
printf "Checking if events that modify the system's mandatory access controls are recorded:\n"
if grep \/etc\/selinux /etc/audit/audit.rules | grep "w /etc/selinux/ -p wa -k MAC-policy" >/dev/null; then
    printf "\e[32mNo remediation needed\e[0m\n"
else 
    echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
    pkill -P 1 -HUP auditd
    printf "\e[32mEvents that modify the system's mandatory access controls are recorded\e[0m\n"
fi

#6.2.1.10 Collect Login and Logout Events
printf "Checking if login and logout events are recorded:\n"
if (grep logins /etc/audit/audit.rules | grep "w /var/log/faillog -p wa -k logins" >/dev/null) && (grep logins /etc/audit/audit.rules | grep "w /var/log/lastlog -p wa -k logins" >/dev/null) && (grep logins /etc/audit/audit.rules | grep "w /var/log/tallylog -p wa -k logins" >/dev/null); then
    printf "\e[32mNo remediation needed\e[0m\n"
else #(Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins)
    echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
    echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
    echo "-w /var/log/tallylog -p wa -k logins" >>  /etc/audit/audit.rules
    pkill -P 1 -HUP auditd
    printf "\e[32mLogin and logout events are recorded\e[0m\n"
fi

#6.2.1.11 Collect session initiation information
printf "Checking if session initiation information is collected:\n"
if (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/run/utmp -p wa -k session" >/dev/null) && (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/log/wtmp -p wa -k session" >/dev/null) && (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/log/btmp -p wa -k session" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
    echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/audit.rules
    echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/audit.rules
    #Execute following command to restart auditd
    pkill -HUP -P 1 auditd
    printf "\e[32mSession initiation information collected\e[0m\n"
fi

#6.2.1.12 Collect discretionary access control permission modification events
printf "Checking if permission modifications are being recorded:\n"
if (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    echo "a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
    #Execute the following command to restart auditd
    pkill -HUP -P 1 auditd
    printf "\e[32mPermission modifications are being recorded\e[0m\n"
fi


#6.2.1.13 Collect unsuccessful unauthorized access attempts to files
printf "Checking if there are unsuccessful attempts to access files:\n"
if (grep access /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >/dev/null) && (grep access /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >/dev/null) && (grep access /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >/dev/null) && (grep access /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
    #Execute following command to restart auditd
    pkill -HUP -P 1 auditd
    printf "\e[32mCollected unsuccessful unauthorised access attempts\e[0m\n"
fi

#6.2.1.14 Collect use of privileged commands
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path="$1" -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules

#6.2.1.15 Collect successful file system mounts
printf "Checking if filesystem mounts are recorded:\n"
if (grep mounts /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >/dev/null) && (grep mounts /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
    #Execute the following command to restart auditd
    pkill -HUP -P 1 auditd
    printf "\e[32mFile system mounts are recorded\e[0m\n"
fi


#6.2.1.16 Collect file deletion events by user
printf "Checking if file deletion events by user are recorded:\n"
if (grep delete /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >/dev/null) && (grep delete /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
    #Execute the following command to restart auditd
    pkill -P 1 -HUP auditd
    printf "\e[32mFile deletion events by user are recorded\e[0m\n"
fi

#6.2.1.17 Collect changes to system administration scope
printf "Checking if changes to /etc/sudoers are recorded:\n"
if grep scope /etc/audit/audit.rules | grep "w /etc/sudoers -p wa -k scope" >/dev/null ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
    #Execute the following command to restart auditd
    pkill -HUP -P 1 auditd
    printf "\e[32mChanges to /etc/sudoers are recorded\e[0m\n"
fi

#6.2.1.18 Collect system administrator actions (syslog)
printf "Checking if administrator activity is recorded:\n"
if grep actions /etc/audit/audit.rules | grep "w /var/log/sudo.log -p wa -k actions" >/dev/null ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
    #Execute the following command to restart auditd
    pkill -HUP -P 1 auditd
    printf "\e[32mAdministratory activities are recorded\e[0m\n"
fi

#6.2.1.19 Collect kernel module loading and unloading
printf "Checking if kernel module loading and unloading are recorded:\n"
if (grep modules /etc/audit/audit.rules |grep "w /sbin/insmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/rmmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/modprobe -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/insmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
    echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
    echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
    echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
    printf "\e[32mKernal module loading and unloading are recorded\e[0m\n"
fi

#6.2.1.20 Make the audit configuration immutable
printf "Checking if audit configuration is immutable:\n"
if grep "^-e 2" /etc/audit/audit.rules >/dev/null; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Add the following lines to /etc/audit/audit.rules file
    echo "-e 2" >> /etc/audit/audit.rules
    printf "\e[32mAudit configuration is immutable\e[0m\n"
fi

#6.2.1.21 Configure logrotate
printf "Checking if appropriate system logs are rotated:\n"
if (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/messages" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/secure" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/maillog" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/spooler" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/boot.log" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/cron" >/dev/null) ; then
    printf "\e[32mNo remediation needed\e[0m\n"
else #Edit the /etc/logrotate.d/syslog file to include appropriate system logs
    echo "/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron {" >> /etc/logrotate.d/syslog
    printf "\e[32mAppropriate system logs are rotated\e[0m\n"
fi
