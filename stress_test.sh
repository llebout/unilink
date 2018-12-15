while true;
do
	nc 127.0.0.1 57052 1>&2 2>/dev/null </dev/urandom;
done
