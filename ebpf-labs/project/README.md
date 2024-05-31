1. create topo by running `./create-topo.sh`
   this creates a virtual interface for each ip in the config as well for the vip
   this is probably not necessary, and actually does not work as intended. I would expect the packets coming from the loadbalancer back to the host to be forwarded to their appropriate namespace,
   but the packets are not being forwarded. Maybe it's an issue that we're receiving a packet with our own ip, but idk.

2. start the dummy program on the host (apparently it is needed https://www.spinics.net/lists/netdev/msg625217.html)
   `./dummy` is the hello world example that just just returns `XDP_PASS`.

3. start the loadbalancer in the first namespace `sudo ip netns exec ns1 sudo ./l4_lb -i veth1_ -c config.yaml`

4. (optional) start the receiver on the host to see all the packets coming in `python3 ./receive.py`
