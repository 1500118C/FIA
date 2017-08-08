#6.2.1.21
printf "Checking if the appropriate system logs are rotated: "
if (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/messages" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/secure" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/maillog" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/spooler" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/boot.log" >/dev/null) && (grep 'var' /etc/logrotate.d/syslog |grep "/var/log/cron" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n" 
else
	printf "\e[31mFAIL\e[0m\n"
fi
