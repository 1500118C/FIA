#6.1.3
printf "Checking if appropriate logging is set: "
if (cat /etc/rsyslog.conf | grep "auth,user.* /var/log/messages" >/dev/null) || (cat /etc/rsyslog.conf | grep "kern.* /var/log/kern.log" >/dev/null) || (cat /etc/rsyslog.conf | grep "daemon.* /var/log/daemon.log" >/dev/null) || (cat /etc/rsyslog.conf | grep "syslog.* /var/log/daemon.log" >/dev/null) || (cat /etc/rsyslog.conf | grep "lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log") ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
