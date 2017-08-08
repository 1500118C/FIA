#6.2.1.6
printf "Checking if system date/time are captured when modified: "
if (egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules | grep "a always, exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >/dev/null) && (egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules | grep "a always, exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >/dev/null) && (egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules | grep "a always, exit -F arch=b64 -S clock_settime -k time-change" >/dev/null) && (egrep 'adjtimex|settimeofday|clock_settime' /etc/audit/audit.rules | grep "a always, exit -F arch=b32 -S clock_settime -k time-change" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
