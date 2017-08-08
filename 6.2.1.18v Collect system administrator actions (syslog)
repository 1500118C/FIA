#6.2.1.18
printf "Checking if administrator activity is recorded: "
if grep actions /etc/audit/audit.rules | grep "w /var/log/sudo.log -p wa -k actions" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
