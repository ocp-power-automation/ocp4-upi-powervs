#!/bin/bash

echo ------------------------------------------
echo "Starting fix_default_route.sh"
echo ------------------------------------------
echo "The public gateway: ${pub_gateway}"

## Record initial routes
route -n >> /tmp/initial_routes

## Perform a public network test
ping -c 5 8.8.8.8 &> /dev/null && echo "Can reach 8.8.8.8" && exit 0 || echo "Cannot reach 8.8.8.8 fixing public network..."

PUB_GW_DEV=`awk "/${pub_gateway}/{ print FILENAME; nextfile }" /etc/sysconfig/network-scripts/ifcfg-* | xargs basename | sed 's/ifcfg-//g'`
echo "Public network device name is $PUB_GW_DEV"

## Fix routes
find /etc/sysconfig/network-scripts -name ifcfg'*' -print0 | xargs -0 sed -i.bak '/GATEWAY/s/^/#/g'
echo "GATEWAY=${pub_gateway}" >> /etc/sysconfig/network
echo "GATEWAYDEV=$PUB_GW_DEV" >> /etc/sysconfig/network

## Reload routes when connection is already available
nmcli connection reload
nmcli networking off
nmcli networking on

echo ------------------------------------------
echo "Ending fix_default_route.sh"
echo ------------------------------------------
