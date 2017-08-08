#6.2.1.19
printf "Checking if kernel module loading and unloading is recorded: "
if (grep modules /etc/audit/audit.rules |grep "w /sbin/insmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/rmmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/modprobe -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "w /sbin/insmod -p x -k modules" >/dev/null) && (grep modules /etc/audit/audit.rules |grep "a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
