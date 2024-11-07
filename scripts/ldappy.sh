#!/bin/bash

# Author: itsnotgunnar 

# Function to display usage instructions
usage() {
    echo "Usage: $0 <IP_ADDRESS> [-u USERNAME] [-p PASSWORD] [-d DOMAIN]"
    echo ""
    echo "Options:"
    echo "  -u, --user USERNAME       Username for LDAP authentication"
    echo "  -p, --password PASSWORD   Password for LDAP authentication"
    echo "  -d, --domain DOMAIN       Domain for LDAP authentication"
    exit 1
}

# Check if at least IP address is provided
if [ -z "$1" ]; then
    usage
fi

# Parse arguments
ip="$1"
shift

# Initialize variables
user=""
pass=""
dom=""
auth_options=""
filename_prefix=""

# Loop through arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u|--user)
            user="$2"
            shift 2
            ;;
        -p|--password)
            pass="$2"
            shift 2
            ;;
        -d|--domain)
            dom="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Prepare authentication options if credentials are provided
if [ -n "$user" ] && [ -n "$pass" ] && [ -n "$dom" ]; then
    auth_options="-D ${user}@${dom} -w ${pass}"
    filename_prefix="${user}_"
    echo "Using authentication with user: ${user}@${dom}"
elif [ -n "$user" ] || [ -n "$pass" ] || [ -n "$dom" ]; then
    echo "Error: To use authentication, please provide all of -u/--user, -p/--password, and -d/--domain."
    exit 1
else
    echo "Proceeding without authentication."
fi

# Step 1: Get naming contexts
namingcontexts=$(ldapsearch -x -H ldap://$ip -s base namingcontexts 2>/dev/null | grep -i '^namingcontexts:' | head -n1 | awk '{print $2}')

if [ -z "$namingcontexts" ]; then
    echo "Failed to retrieve naming contexts from LDAP server at $ip"
    exit 1
fi

echo "Using base DN: $namingcontexts"

# Step 2: Run LDAP queries

# Full LDAP query
echo "Running full LDAP query..."
ldapsearch -x -H ldap://$ip $auth_options -b "$namingcontexts" > "${filename_prefix}full-ldap.txt"

# LDAP query for objectClass=Person
echo "Running LDAP query for objectClass=Person..."
ldapsearch -x -H ldap://$ip $auth_options -b "$namingcontexts" "(objectClass=Person)" > "${filename_prefix}person-ldap.txt"

# Define patterns to exclude
exclude_patterns="objectClass|distinguishedName|instanceType|whenCreated|whenChanged|uSNCreated|uSNChanged|objectGUID|userAccountControl|codePage|countryCode|objectSid|accountExpires|sAMAccountType|isCriticalSystemObject|dSCorePropagationData|lastLogonTimestamp|showInAdvancedViewOnly|groupType|msDS-SupportedEncryptionTypes|lastLogoff|badPasswordTime|ref:|# num|# search|search:|result:"

# Filtered LDAP query with password-related attributes
echo "Extracting password-related attributes..."
ldapsearch -x -H ldap://$ip $auth_options -b "$namingcontexts" 2>/dev/null | \
    grep -viE "$exclude_patterns" | \
    grep -iE "pass|pwd" | tee "${filename_prefix}password-attributes.txt"

# General filtered LDAP query
echo "Running general filtered LDAP query..."
ldapsearch -x -H ldap://$ip $auth_options -b "$namingcontexts" 2>/dev/null | \
    grep -viE "$exclude_patterns" > "${filename_prefix}filtered-ldap.txt"

# Filtered LDAP query for objectClass=Person
echo "Running filtered LDAP query for objectClass=Person..."
ldapsearch -x -H ldap://$ip $auth_options -b "$namingcontexts" "(objectClass=Person)" 2>/dev/null | \
    grep -viE "$exclude_patterns" > "${filename_prefix}filtered-person-ldap.txt"

echo "LDAP queries completed. Output files generated:"
echo "- ${filename_prefix}full-ldap.txt"
echo "- ${filename_prefix}person-ldap.txt"
echo "- ${filename_prefix}password-attributes.txt"
echo "- ${filename_prefix}filtered-ldap.txt"
echo "- ${filename_prefix}filtered-person-ldap.txt"
