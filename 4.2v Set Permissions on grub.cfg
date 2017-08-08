#4.2
printf "Checking if grub.cfg file is set to read and write for root only: "
if stat -L -c "%a" /boot/grub2/grub.cfg | grep "00" >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[31mFAIL\e[0m\n"
fi
