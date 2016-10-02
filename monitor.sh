#!/bin/bash

# If the resolver doesn't resolve; container kills itself.

TIMEOUT=20
MYIP=""
function myaddress {
  while [[ "${MYIP}X" == "X" ]] && [[ "${TIMEOUT}" -gt 0 ]]; do
    echo "Trying ${TIMEOUT}"
    MYIP="`networkctl status ${SINKIT_KRESD_NIC:-eth0} | awk '{if($1~/Address:/){printf($2);}}'`"
    export MYIP
    let TIMEOUT=$TIMEOUT-1
    if [[ "${MYIP}" == ${SINKIT_ADDR_PREFIX:-10}* ]]; then
      break;
    else
      MYIP=""
      sleep 1;
    fi
  done
  echo -e "MYIP: ${MYIP}\nMYNIC: ${SINKIT_KRESD_NIC:-eth0}"
  if [[ "${MYIP}X" == "X" ]]; then
    echo "${SINKIT_KRESD_NIC:-eth0} Interface error. "
    exit 1
  fi
}

SUCCESS=0
function checkit {
    SUCCESS=`dig seznam.cz @${MYIP} | grep -P -c "ANSWER: [1-9]+"`
    if [[ "$SUCCESS" < 1 ]]; then
        SUCCESS=`dig google.com @${MYIP} | grep -P -c "ANSWER: [1-9]+"`
    fi
}


echo "Getting address..."
myaddress

echo "Initial checking..."
while [[ "$SUCCESS" < 1 ]]; do
    echo "Checking resolver's sanity..."
    checkit
    sleep 1
done

echo "From now on, any failure means container teardown."

FAIL_COUNTER=0
while [[ 1 ]]; do
    checkit
    if [[ "$SUCCESS" > 0 ]]; then
        FAIL_COUNTER=0
    else
        let FAIL_COUNTER=$FAIL_COUNTER+1
    fi
    if [[ "$FAIL_COUNTER" > 1 ]]; then
        kill -9 1
    fi
    sleep 5
done

