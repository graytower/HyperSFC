# HyperSFC
State-Intensive Service Function Chaining on Hyper-Converged Edge Infrastructure

Network functions(NFs) are prevalent in edge and public cloud, such as cloud gateways and load balancers. Although software-based NFs have the advantages of flexibility, shorter development cycles, and lower costs, they are limited by the processing performance of commercial CPUs and inter-core communication, making it challenging to achieve line-rate processing for target applications. Emerging P4ASIC-based NFs exhibit superior forwarding performance. However, they are constrained by the limited memory resources of ASIC, making it difficult to offload NFs carrying a large number of table entries onto the ASIC. So we propose HyperSFC, a state-intensive service function chaining on hyper-converged edge infrastructure. Specifically, leveraging the ultra-low latency between the ASIC and CPU in the hyper-converged gateway, we place the entire table on the CPU and the hot table on the ASIC. For the packets that miss in the ASIC, we obtain the lookup result through a round-trip process. Furthermore, we adopt the lazy-submit strategy to insert multiple consecutive miss table information into the packets and design a branch selector to address pipeline branching issues. Evaluation results demonstrate that HyperSFC reduces latency by 30% and lowers CPU utilization to less than 3% . Compared to the non-extension model, P4Swell incurs a lower latency overhead in exchange for a significantly larger table storage space.

# Preset for system
This demo include Busy-submit, Lazy-submit and HyperSFC LB.

HyperSFC put some table entries in Redis and store them in the format of "key-action-parameter", for example: in redis, execute the command: 

set 10.0.3.3 MyIngress.ipv4_forward,08:00:00:00:03:33,3 

This is a example of ipv4 forward, "MyIngress.ipv4_forward" is the action, and "08:00:00:00:03:33,3" are the parameter of forward(dst_MAC and egress port).

# Here are the steps to run HyperSFC:

1.Configure the flow table in Redis.

2.auto dump flow table entries:

cd packet sudo ./dump

3.start mininet: 

make 

xterm h1 h2 h3 //h1-sendipv4 h2-recv h3-recv_ipv4

h2: cd packet ./recv_busy(./recv_lazy or ./recv_lb)

h3: cd packet ./recv_ipv4

h1: cd packet ./send_ipv4

Then, you will find that although the switch started without inserting all the table entries, it still completed the correct forwarding.
