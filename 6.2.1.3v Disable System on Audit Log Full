#6.2.1.3
printf "Checking if space_left_action = email: "
if grep space_left_action /etc/audit/auditd.conf | grep "email" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking the action_mail_acct = root: "
if grep action_mail_acct /etc/audit/auditd.conf | grep "root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if admin_space_left_action = halt: "
if grep admin_space_left_action /etc/audit/auditd.conf | grep "halt" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
