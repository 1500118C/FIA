#6.2.1.7
printf "Checking if modifying user/group information are recorded: "
if (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/group -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/passwd -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/gshadow -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/shadow -p wa -k identity" >/dev/null) && (egrep '\/etc\/group|\/etc\/passwd|\/etc\/gshadow|\/etc\/shadow|\/etc\/security\/opasswd' /etc/audit/audit.rules | grep "w /etc/security/opasswd -p wa -k identity" >/dev/null) ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
