#!/bin/bash

source /usr/src/config/.env

# old_ip=$(ip -br a | grep eth0 | awk '{print $3}')
# ip address del $old_ip dev eth0
# ip address add "$IP_ADDR/24" dev eth0
route add default gw "$DEF_GATE" dev eth0
sleep 365d
