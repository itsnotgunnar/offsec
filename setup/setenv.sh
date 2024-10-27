#!/bin/bash

# Typing out usernames and passwords was driving me crazy.
# This turns bash suggestions into an absolute warrior for most or many of the commands I run. 

# Example usage:
#   source /opt/setenv.sh <ip> <domain> <dc>
#   source /opt/setenv.sh <ip> <domain> <dc> <user> <pass>

# Assign positional arguments to variables
export ip="$1"
export dom="$2"
export dc="$3"

# Assign optional arguments if provided
export user="$4"
export pass="$5"

# Check if 'dom' is unset or empty, set 'url' accordingly
if [[ -z "$dom" ]]; then
    export url="http://$ip"
else
    export url="http://$dom"
fi
