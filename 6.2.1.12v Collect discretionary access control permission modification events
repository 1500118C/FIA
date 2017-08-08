#6.2.1.12
printf "Checking if permission modifications are being recorded: "
if (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) && (grep perm_mod /etc/audit/audit.rules | grep "a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
