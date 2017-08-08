#5.1
printf "Checking if core dumps are restricted: \n"
grep "hard" /etc/security/limits.conf
printf "fs.suid_dumpable == 0? "
if sysctl fs.suid_dumpable >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
