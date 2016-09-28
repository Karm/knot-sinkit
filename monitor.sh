#!/bin/bash

# If the resolver doesn't resolve; container kills itself.

SUCCESS=0
function checkit {
    local address="`grep "Using address:" /var/log/kresd-stdout.log | tail -n1 | sed 's/Using address: \(.*\)/\1/g'`"
    SUCCESS=`dig seznam.cz @${address} | grep -P -c "ANSWER: [1-9]+"`
    if [[ "$SUCCESS" < 1 ]]; then
        SUCCESS=`dig google.com @${address} | grep -P -c "ANSWER: [1-9]+"`
    fi
}

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

