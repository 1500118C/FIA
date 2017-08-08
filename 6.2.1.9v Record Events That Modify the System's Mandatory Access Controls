#6.2.1.9
printf "Checking if modification of system's mandatory access controls are recorded: "
if grep \/etc\/selinux /etc/audit/audit.rules | grep "w /etc/selinux/ -p wa -k MAC-policy" >/dev/null; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
