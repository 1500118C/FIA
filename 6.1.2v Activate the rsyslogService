#6.1.2
printf "Checking if rsyslog is enabled: "
if systemctl is-enabled rsyslog | grep "enabled" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
