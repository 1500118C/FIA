#6.1.5
printf "Checking if rsyslog sends logs to remote log host: "
if grep "^*.*[^|][^|]*@" /etc/rsyslog.conf >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
