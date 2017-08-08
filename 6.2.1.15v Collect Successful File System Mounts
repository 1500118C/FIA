#6.2.1.15
printf "Checking if filesystem mounts are recorded: "
if (grep mounts /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >/dev/null) && (grep mounts /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
