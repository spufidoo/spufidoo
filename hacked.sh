#!/bin/bash
journalctl _COMM=sshd --since=yesterday --until=today | grep 'Failed password for invalid user ' | awk '{print $11}' > /tmp/Failed
journalctl _COMM=sshd --since=yesterday --until=today | grep 'Failed password for ' | grep -v 'invalid user' | awk '{print $9}'  >> /tmp/Failed

/usr/sbin/sendmail pi <<END
Subject: Hacking attempts
To: Marcus Davage <marcus@davage.me>
From: pivpn <pi@pivpn.local>
Here is the hacking report for $(date --date=yesterday)
------------------------------------------------------------
`/usr/bin/python3 /usr/local/bin/hacked.py`

Here's the list of invalid user id attempts:
--------------------------------------------
`sort /tmp/Failed | uniq -c | sort -n && rm /tmp/Failed`

https://www.abuseipdb.com/user/51468

Now wash your hands.
END
