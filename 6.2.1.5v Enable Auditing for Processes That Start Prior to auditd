#6.2.1.5
printf "Checking if /boot/grub2/grub.cfg is configured to log: "
if grep "[[:space:]]linux" /boot/grub2/grub.cfg | grep "audit=1" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
