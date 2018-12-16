while true;
do
	nc 127.0.0.1 "$1" 2>&1 1>/dev/null << msg
unilink
0
0
Greetings!
I am a member of the unilink network.
0

msg
done
