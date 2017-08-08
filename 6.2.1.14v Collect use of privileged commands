#6.2.1.14
printf "Checking if privileged commands are in audit: "
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit-F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' > /tmp/1.log

checkpriviledge=`cat /tmp/1.log`
cat /etc/audit/audit.rules | grep -- "$checkpriviledge" > /tmp/2.log

checkpriviledgenotinfile=`grep -F -x -v -f /tmp/2.log /tmp/1.log`

if [ -n "$checkpriviledgenotinfile" ]
then
	printf "\e[31mFAIL\e[0m\n"
else
	printf "\e[32mPASS\e[0m\n"
fi

rm /tmp/1.log
rm /tmp/2.log
