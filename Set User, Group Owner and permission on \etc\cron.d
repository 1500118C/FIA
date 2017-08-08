#!/bin/bash 
#9.6 Set User/Group Owner and Permission on /etc/cron.d
printf "Checking if the /etc/cron.d directory has the correct permissions:\n"
if ls -ld /etc/cron.d | grep -e drwx------ ; then # Modify the file permissions to allow only users to read, write and execute
    printf "\e[32mNo remediation needed\e[0m\n"
else
    chown root:root /etc/cron.d
    chmod og-rwx /etc/cron.d
    printf "\e[32mChanged to correct permission\e[0m\n"
fi
