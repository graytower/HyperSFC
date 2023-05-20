Busy-submit policy allows packets to be sent to the CPU of the converged gateway to look up the tables when matching miss in the switch.

HyperSFC put some table entries in Redis and store them in the format of "key-action-parameter", for example:
in redis, execute the command:
set 10.0.3.3 MyIngress.ipv4_forward,08:00:00:00:03:33,3
this is a example of ipv4 forward, "MyIngress.ipv4\_forward" is the action, and "08:00:00:00:03:33,3" are the parameter of forward(dst\_MAC and egress port)

Here are the steps to run Busy-submit of HyperSFC:

1.Configure the flow table in Redis.

2.auto dump flow table entries:
cd packet
sudo ./dump

3.start mininet:
make
xterm h1 h2 h3  //h1-sendipv4 h2-recv_busy h3-recvipv4

h2:
cd packet
./recv_busy

h3:
cd packet
./recv_ipv4

h1:
cd packet
./send

then, you will find that although the switch started without inserting all the table entries, it still completed the correct forwarding.
