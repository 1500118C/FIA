#6.2.1.20
printf "Checking if the audit configuration is immutable: "
if grep "^-e 2" /etc/audit/audit.rules >/dev/null; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
