while true;
do
	cat /dev/urandom | nc 127.0.0.1 57052
done
