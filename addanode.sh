#!/bin/bash -x

set -o pipefail

# determine the domain name
hostname=`hostname`
DOMAIN=${hostname%"-bastion-0.ibm.com"}

# check if the cluster is more than 24 hrs old
if ( ! type -P oc ); then exit 0; fi
oc get -o json clusterversion version > /tmp/test.$$ 2> /dev/null
if  [ ! -f /tmp/test.$$ ]; then
    echo "open cluster not set"
    exit 0
fi

tmstmp_str=$(cat /tmp/test.$$ | jq -r '.metadata.creationTimestamp')
[ -z $tmstmp_str ] && exit 0
tmstmp=`date -d$tmstmp_str +%s`

if (( $tmstmp  + 86400 < `date +%s` )); then
    #preserve the timestamp of the file
    echo "create a new certificate"
    if [ ! -f openstack-upi/.worker.ign.backup ]; then
        cp -p openstack-upi/worker.ign openstack-upi/.worker.ign.backup
    fi

    #update the tls certificate in the worker ignition file
    URL=api-int.${DOMAIN}
    #openssl s_client -connect ${URL}:22623 -showcerts </dev/null 2>/dev/null|openssl x509 -outform PEM > /tmp/api-int.pem
    #base64 --wrap=0 /tmp/api-int.pem 1> /tmp/api.int.base64
    #unset IGKEY
    #export IGKEY=`cat /tmp/api.int.base64`
    #data=`cat openstack-upi/.worker.ign.backup | jq ".ignition.security.tls.certificateAuthorities[].source=\"data:text/plain;charset=utf-8;base64, $IGKEY\""`
    #echo -e $data | tr -d [:space:] > openstack-upi/worker.ign

    MCS=api-int.${DOMAIN}:22623
    echo "q"                                                        | \
    openssl s_client -connect $MCS  -showcerts                      | \
    awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' | \
    base64 --wrap=0                                                 | \
    tee ./api-int.base64 && sed --regexp-extended --in-place=.backup "s%base64,[^,]+%base64,$(cat ./api-int.base64)\"%" ./worker.ign

    # Copy Ignition Files to HTTP server
    cp openstack-upi/worker.ign /var/www/html/ignition

    chmod 777 /var/www/html/ignition/*.ign

    # Check, if download would succeed from your http server.
    #curl -I http://130.198.121.90:8080/worker.ign
fi

# check the worker count
total_workers=`cat /etc/dhcp/dhcpd.conf | grep worker | wc -l | tr -d ' '`
no_of_workers=`oc get nodes | grep worker* | grep Ready |  grep  -v "NotReady" | wc -l | tr -d ' '`
echo "total workers=[${total_workers}]" 
echo "no_of_workers=[${no_of_workers}]" 

while (( ${no_of_workers} != ${total_workers} )); do 
    oc get csr -o name | xargs oc adm certificate approve
    no_of_workers=`oc get nodes | grep worker | grep Ready |  grep  -v "NotReady" | wc -l | tr -d ' '`
    echo -ne "no_of_worker=${no_of_workers}, total_worker=${total_workers}. waiting for 20 seconds..."\\r
    sleep 20
done
