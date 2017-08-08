#6.2.1.2
printf "Checking if audit logs are retained: "
if grep max_log_file_action /etc/audit/auditd.conf | grep "keep_logs" > /dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
