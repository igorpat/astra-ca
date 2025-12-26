#!/bin/bash

function signal_handle() {  
    echo "signal: $1"
    # Дополнительный код обработки ошибок  
    echo $(date) >> /var/log/pki-tomcatd.log
    exit 0
}
trap 'signal_handle "Something went wrong!"' INT

#mktemp
echo $(date) > /var/log/pki-tomcatd.log
while true; do
    echo -n "-" >> /var/log/pki-tomcatd.log 
    sleep 1
done
