#!/bin/bash

echo ------------------------------------------
echo "Starting fix_default_route.sh"
echo ------------------------------------------
echo "The public gateway: ${pub_gateway}"

for device in $(nmcli device | grep ethernet | awk '{print $1}'); do

    ifcfg_file=/etc/sysconfig/network-scripts/ifcfg-$device
    gateway=$(grep GATEWAY /etc/sysconfig/network-scripts/ifcfg-$device | cut -d= -f2)
    defroute=$(grep DEFROUTE /etc/sysconfig/network-scripts/ifcfg-$device | cut -d= -f2)
    echo "Looping DEVICE: $device GATEWAY: $gateway DEFROUTE: $defroute"

    if [[ $gateway == ${pub_gateway} ]]; then
        echo "This is a public interface: $device"
        if [[ $defroute == "no" ]]; then
            echo "Changing DEFROUTE=yes for public interface: $device"
            sed -i 's/DEFROUTE=no/DEFROUTE=yes/g' $ifcfg_file
        fi
    elif [[ ! -z $gateway ]]; then
        echo "This is other interface(not public) : $device"
        if [[ $defroute == "yes" ]]; then
            echo "Changing DEFROUTE=no for other interface: $device"
            sed -i 's/DEFROUTE=yes/DEFROUTE=no/g' $ifcfg_file
            # Force delete the private route in case network is already configured
            ip route del default via $gateway | true
        fi
    else
        echo "No gateway, ignoring this interface: $device"
    fi
done

echo ------------------------------------------
echo "Ending fix_default_route.sh"
echo ------------------------------------------

