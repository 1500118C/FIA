#6.2.1.17
printf "Checking if changes to /etc/sudoers are recorded: "
if grep scope /etc/audit/audit.rules | grep "w /etc/sudoers -p wa -k scope" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
