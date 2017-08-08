#6.1.6
printf "Checking if rsyslog is listening for remote messages: "
printf "ModLoad imtcp.so: "
if grep '$ModLoad imtcp.so' /etc/rsyslog.conf >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi

printf "InputTCPServerRun 514: "
if grep '$InputTCPServerRun' /etc/rsyslog.conf >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
