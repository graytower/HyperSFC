full table entries:
redis-cli
keys *

auto dump flow table entries:
cd packet
sudo ./dump

start mininet:
make
xterm h1 h2 h3  //h1-sendipv4 h2-CPU_lookup h3-recvipv4

h2:
cd packet
./recv_lazy

h3:
cd packet
./recv_ipv4

h1:
cd packet
./send

