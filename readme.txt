
https://pypi.org/project/NetfilterQueue/

apt-get install build-essential python-dev libnetfilter-queue-dev

iptables -I <table or chain> <match specification> -j NFQUEUE --queue-num <queue number>
iptables -I INPUT -d 192.168.0.0/24 -j NFQUEUE --queue-num 1
