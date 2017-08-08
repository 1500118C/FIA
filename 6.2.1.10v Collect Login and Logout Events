#6.2.1.10
printf "Checking if login and logout events are recorded: "
if (grep logins /etc/audit/audit.rules | grep "w /var/log/faillog -p wa -k logins" >/dev/null) && (grep logins /etc/audit/audit.rules | grep "w /var/log/lastlog -p wa -k logins" >/dev/null) && (grep logins /etc/audit/audit.rules | grep "w /var/log/tallylog -p wa -k logins" >/dev/null); then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
