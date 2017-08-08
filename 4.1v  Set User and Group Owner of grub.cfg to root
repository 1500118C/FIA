#4.1
printf "Checking if grub.cfg belongs to root: "
if stat -L -c "owner=%U group=%G" /boot/grub2/grub.cfg | grep "owner=root group=root" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
