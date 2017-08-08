#6.2.1.16
printf "Checking if file deletion events by user are recorded: "
if (grep delete /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >/dev/null) && (grep delete /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"	
else
	printf "\e[31mFAIL\e[0m\n"
fi
