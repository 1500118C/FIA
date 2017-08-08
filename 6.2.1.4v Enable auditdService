#6.2.1.4
printf "Checking if auditd is enabled: "
if systemctl is-enabled auditd | grep "enabled" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
