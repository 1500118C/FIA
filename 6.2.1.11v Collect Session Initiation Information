#6.2.1.11
printf "Checking if session initiation information is collected: "
if (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/run/utmp -p wa -k session" >/dev/null) && (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/log/wtmp -p wa -k session" >/dev/null) && (egrep 'wtmp|btmp|utmp' /etc/audit/audit.rules | grep "w /var/log/btmp -p wa -k session" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
