#!/bin/bash

# If the resolver doesn't resolve; container kills itself.

SUCCESS=0
function checkit {
    SUCCESS=`dig seznam.cz @\`grep "Using address:" /var/log/kresd-stdout.log | tail -n1 | sed 's/Using address: \(.*\)/\1/g'\` | grep -P -c "ANSWER: [1-9]+"`
}

echo "Initial checking..."
while [[ "$SUCCESS" < 1 ]]; do
    echo "Checking resolver's sanity..."
    checkit
    sleep 1
done

echo "From now on, any failure means container teardown."

while [[ 1 ]]; do
    echo "Checking resolver's sanity..."
    checkit
    if [[ "$SUCCESS" > 0 ]]; then
        echo "OK"
    else
        kill -9 1
    fi
    sleep 5
done

