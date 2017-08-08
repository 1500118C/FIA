#6.1.4
printf "Checking if /var/log/messages is root root: "
if ls -l /var/log/messages | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/messages is 600: "
if stat -c "%a %n"  /var/log/messages | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/messages is 640: "
if stat -c "%a %n"  /var/log/messages | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/secure is root root: "
if ls -l /var/log/secure | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/secure is 600: "
if stat -c "%a %n"  /var/log/secure | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/secure is 640: "
if stat -c "%a %n"  /var/log/secure | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/maillog is root root: "
if ls -l /var/log/maillog | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/maillog is 600: "
if stat -c "%a %n"  /var/log/maillog | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/maillog is 0640: "
if stat -c "%a %n"  /var/log/maillog | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/cron is root root: "
if ls -l /var/log/cron | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/cron is 600: "
if stat -c "%a %n"  /var/log/cron | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/cron is 640: "
if stat -c "%a %n"  /var/log/cron | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/spooler is root root: "
if ls -l /var/log/spooler | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/spooler is 600: "
if stat -c "%a %n"  /var/log/spooler | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/spooler is 640: "
if stat -c "%a %n"  /var/log/spooler | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/boot.log is root root: "
if ls -l /var/log/boot.log | grep "root root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/boot.log is 600: "
if stat -c "%a %n"  /var/log/boot.log | grep "600" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "Checking if /var/log/boot.log is 640: "
if stat -c "%a %n"  /var/log/boot.log | grep "640" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
