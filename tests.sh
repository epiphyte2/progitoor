#!/bin/bash

set -e

cd $( dirname "${BASH_SOURCE[0]}" )

GROUP=$( id -gn )

rm -rf ./underlay

mkdir -p ./underlay
mkdir -p ./overlay

./target/debug/progitoor ./underlay ./overlay --loglevel Debug

while ! mountpoint -q ./overlay; do
    echo "Waiting for mount..."
    sleep 1
done

function cleanup {
    echo "Cleanup up..."
    umount ./overlay
    while mountpoint -q ./overlay; do
        echo "Waiting for unmount..."
        sleep 1
    done
    rm -rf ./underlay
    echo "Done."
}

trap cleanup EXIT

# usage: check <file> <mode> <user> <group>
function check {
    stat -c "%a %U %G" $1 | while read M U G; do
        echo check for $1: $M $U $G
        RET=0
        if [ "$2" != "$M" ]; then
            echo "check failed for $1: mode $2 != $M"
            RET=1
        fi
        if [ "$3" != "$U" ]; then
            echo "check failed for $1: user $3 != $U"
            RET=1
        fi
        if [ "$4" != "$G" ]; then
            echo "check failed for $1: group $4 != $G"
            RET=1
        fi
        return $RET
    done
    return $?
}

# Tests

F=./overlay/foo
echo "foo" > $F
check $F 664 ${USER} ${GROUP}
sudo chown root $F
check $F 664 root ${GROUP}
sudo chmod 600 $F
check $F 600 root ${GROUP}
