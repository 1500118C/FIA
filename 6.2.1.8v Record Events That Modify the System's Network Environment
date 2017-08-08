#6.2.1.8
printf "Checking if modification of the system's environment are recorded: "
if (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/issue -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/issue.net -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/hosts -p wa -k system-locale" >/dev/null) && (egrep 'sethostname | setdomainname |\/etc\/issue|\/etc\/hosts|\/etc\/sysconfig\/network' /etc/audit/audit.rules | grep "w /etc/sysconfig/network -p wa -k system-locale" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
