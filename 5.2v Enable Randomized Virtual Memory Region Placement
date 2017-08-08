#5.2
printf "Checking if virtual memory is randomized: "
if sysctl kernel.randomize_va_space >/dev/null ; then
	printf "\e[32mPASS\e[0m\n"
else
	printf "\e[32mFAIL\e[0m\n"
fi
