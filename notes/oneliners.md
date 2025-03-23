## Bash One-Liners

Smile.

#### Take the second field out output

```bash
cat file.txt | awk '{print $2}'
```

#### Tee output to file and stout

```bash
enum4linux | tee file.txt
```

#### Recursively replace all spaces in dir names

```bash
find . -depth -name "* *" -execdir rename 's/ /_/g' "{}" \;
```

#### Iteratitively Create Files with Dates of the Past Year

```bash
for i in $(seq 330 695); do date --date="$i day ago" +%Y-%m-%d-upload.pdf; done > datefile
```

#### Remove part of common directory names

```bash
find . -depth -type d -name '*NAME*' | while IFS= read -r file; do new_name=$(echo "$file" | sed 's/NAME//'); mv "$file" "$new_name"; done
```

#### Concatenate all videos in a directory (if spaces in file/directory name)

```bash
find . -name "*.webm" | sort -V > videos.txt && sleep 1 && sed "s/^file \(.*\)$/file '\1'/" "videos.txt" > "tmp.txt" && sleep 1 && mv tmp.txt videos.txt && sleep 1 && ffmpeg -f concat -safe 0 -i videos.txt -c copy automatedRemidiation.webm
```

#### Trim Video

```bash
ffmpeg -i input.mp4 -ss 00:06:00 -t 00:01:00 -c copy output.mp4
```

#### Write Metadata to File

```bash
setfattr -n user.metadata_key -v "value" file
getfattr -d file
```

#### Decrypt VNC Password

```bash
echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
```

#### Find largest files on fs

```bash
sudo find / -type f -exec du -h {} + | sort -rh | head -n 50
```

#### Find largest directories on your fs, not including root dirs and their child

```bash
sudo du -ah / | grep -vE '^(/[^/]+/[^/]+)$' | sort -rh | head -n 20
```

#### Find 50 largest duplicate files on filesystem

```bash
sudo find / -type f -exec md5sum {} + 2>/dev/null | sort | uniq -w32 -dD | awk '{print $2}' | xargs -I{} du -b {} | sort -n | head -n 30
```

#### Delete files that don't match a pattern or file extension

```bash
rm !(*.foo|*.bar|*.baz)
```

#### Show process that use internet connection at the moment

```bash
lsof -P -i -n
```

#### Show process that use specific port number

```bash
lsof -i tcp:443
```

#### Lists all listening ports together with the PID of the associated process

```bash
lsof -Pan -i tcp -i udp
```

#### Convert uppercase files to lowercase files.

```bash
rename 'y/A-Z/a-z/' *
```

#### Lines only present in file1 or file2 (not in both)

```bash
comm -3 recently_modified_files.txt non_root_owned_directories.txt
```

#### Password to NTLM

```bash
import hashlib; print(hashlib.new('md4', 'ENTER_PASSWORD'.encode('utf-16le')).digest().hex())
```

#### Grep Commands

Recursively Grep for word, case insensitive, show 3 lines before and after match

```bash
grep -ri "word" location -A3 -B3
```

Print only the matched pattern.

```bash
grep -o "35.237.4.214" log.txt
```

Print only numbers that are in groups of 1-4.

```bash
grep -Eo '[0-9]{1,4}' log.txt
```

Show lines that don't have words.

```bash
cat file.txt | grep -v "word1\|word2\|word3"
```

Find filename, case insensitive, with size.

```bash
ll $(find /opt/SecLists) | grep -i "wordpress"
```

Keeps lines that have a capital letter, a special character, and a number.

```bash
cat input.txt | grep -P '[A-Z]' | grep -P '[^a-zA-Z0-9]' | grep -P '[0-9]'
```

Look at all of the directories:

```bash
ls -alR | grep ^d
```

#### Slicing and Dicing Text Files & Output

Remove duplicate lines.

```bash
awk '!seen[$0]++' users.txt
awk '{line=tolower($0)} !seen[line]++' # case insensitive
```

Print without newline, replace with comma.

```bash
cat us.txt|awk -F'\n' '{printf "%s,",$1}'
```

Trim leading and trailing whitespace, delete blank lines, squeeze tabs and bunch of spaces into single space.

```bash
awk 'NF{$1=$1};1' users.txt   
```

Trim leading and trailing whitespace, squeeze tabs and bunch of spaces into single space.

```bash
awk '{$1=$1};1' users.txt   
```

Delete blank lines.

```bash
tr -s -c ' ' users.txt
awk '{print $5}' | tr -s -c ' ' users.txt
```

Capitalize the first letter of every word.

```bash
awk '{ for(i=1; i<=NF; i++) $i = toupper(substr($i,1,1)) substr($i,2) } 1' users.txt
```

Make txt file of words lowercase and remove duplicates without ordering the words.

```bash
awk '!a[tolower($0)]++ {print tolower($0)}' input.txt > output.txt
awk '!a[toupper($0)]++ {print toupper($0)}' users.txt
```

Cat the 1st and 3rd field separated by ':':

```bash
cat creds.txt| cut -d ":" -f 1,3
```

Remove any words from txt file that are less than 6 chars.

```bash
awk 'length($0) >= 6' passwords.txt > temp.txt && mv temp.txt passwords.txt
```

Prepend the special chars '^$' at the beginning of each word in a text file from lines 106 to 122.

```bash
sed -i '89,105s|^|^$|' bdg.rule
```

Every combination of words from file1 and file2, separated by a colon, with outer loop being users, then removing any words in file2 that aren't 7 letters and have a capital letter and a special char, without ordering.

```bash
awk 'length($0) >= 7' passwords.txt > tmp_passwords.txt && awk 'NR==FNR {a[$1]; next} {for (i in a) print $1 ":" i}' tmp_passwords.txt users.txt | grep -P '[A-Z]' | grep -P '[^a-zA-Z0-9]' > combined.txt && rm tmp_passwords.txt
```

Combining two files' lines with a ':'.

```bash
awk 'NR==FNR {a[$1]; next} {for (i in a) print i ":" i}' users.txt users.txt > combo.txt    
```

Make a txt file of all port numbers.

```bash
seq 1 65535 > ports.txt
```

Combine all files named passwords.txt.

```bash
find /home/kali/practice -name "passwords.txt" -exec cat {} \; > megapasswords.txt
```

Prepends file1 to the beginning of file2.

```bash
cat file1 file2 > file3
```

Remove words from text file that start with '$2a'.

```bash
sed -i '/^\$2a/d' filename.txt
```

Print lines 90-870.

```bash
sed -n '90,870p' filename.txt
awk 'NR >= 90 && NR <= 870' filename.txt > output.txt
```

Remove all words that start with $ and are longer than 25 chars.

```bash
awk '{ for (i = 1; i <= NF; i++) if (!($i ~ /^\$.{25,}/)) printf "%s ", $i; printf "\n"}' filename.txt > output.txt
```

Clean all the weird files in linux lfi txt file list to the interesting files:

```bash
cat files.txt |grep -i 'etc\|conf\|ini\|cnf\|var' |grep -v '\\\|\%\|//\|\.\.\|\?\|x'> /home/kali/repos/offsec/lists/lfi-condensed-tmp.txt && awk '!seen[$0]++' /home/kali/repos/offsec/lists/lfi-condensed-tmp.txt > /home/kali/repos/offsec/lists/lfi-condensed.txt && rm /home/kali/repos/offsec/lists/lfi-condensed-tmp.txt
```

Delete the last line in a file, or particular ones.

```bash
sed '$d' log.txt # -i would delete the line of the file in-place
sed '5,7d' log.txt
```

Print specific lines.

```bash
sed -n '2,15 p' log.txt
```

#### Vi Magic

Get rid of spaces.

```bash
:%s/ //g
```

Substitute "|" with newline.

```bash
:%s/|/\r/g
```

Replace strings.

```bash
:%s/^t/,/g # Replace tabs with commas globally
```

Delete lines that match (or don't match) pattern.
```bash
:g/<pattern>/d
:g!/<pattern>/d
```

Commenting out blocks of code.

```bash
# Enter ma at the start location, go to end of block and enter mb
:'a,.s/^/#
```

Copy block of code, move block of code.

```bash
:'a,'bco . || :'a,'bmo .
```

Yanking to a buffer 'a', or append to buffer 'a'.

```bash
:'a,.ya a || :'a,.ya A
```

Substituting in a block of text.

```bash
:'a,.s/search_string/replace_string/[gc] # g is global and c is confirm functionality
```

Recursively replace pattern/string with another within current directory.

```bash
for fyl in $(find . \( -type d -iregex "^\.git.*\|.*results.*\|.*ResetPassword.*" -prune \) -o -type f); do sed -i 's/192\.168\.172\.21/192\.168\.178\.21/g' $fyl; wait; done
```

I use them all the time for:
    copying and moving blocks of code,
    yanking and deleting blocks of code into named buffers, and
    Edit: substituting in a block of test.


#### Test out su

```bash
users=$(cat /etc/passwd 2>/dev/null | grep -i "sh$" | cut -d ":" -f 1); sucheck(){ sucheck=$(echo "$2" | timeout 1 su $user -c whoami 2>/dev/null); if [ "$sucheck" ]; then echo "  You can login as $user using password: $2" && echo "$1:$2" >> /dev/shm/valid.txt; fi }; printf "%s\n" "$users" | while read user; do sucheck "$user" ""; sucheck "$user" "$user"; sucheck "$user" "$hostname"; sucheck "$user" "$(echo $user | rev 2>/dev/null)"; if [ -f "passwords.txt" ]; then while IFS=' ' read -r guess; do sucheck "$user" "$guess"; sleep 0.01; done < "passwords.txt"; fi; if [ -f "$1" ]; then while IFS=' ' read -r guess; do sucheck "$user" "$guess"; sleep 0.01; done < "$1"; fi; done
```

find ../ResetPassword -type f -exec strings {} \; -exec grep -riH password --color  {} \;