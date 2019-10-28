# exchange_hunter
Hunting For Microsoft Exchange the Long Way

This script uses the Python-Masscan library which requires Masscan to be in the $PATH.

First it scans all RFC-1918 address space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) for open SMTP (25/tcp).

It then scans those hosts with open SMTP for open HTTPS (443/tcp).

It then uses the futures library to make multi-threaded requests to "https://<FOUND-IP>/EWS/Exchange.asmx", which is a Microsoft Exchange specific URL.  IF NTLM Authentication is forced in that request, I.E. if "WWW-Authenticate" is seen in the response headers, then we can with a high certainty say that we have found a Microsoft Exchange server.

This is a recon tool to be used to assist in later attacks on a network.  Maybe PrivExchange, maybe something else.  Need to find the bits and peices before you can put them together, right?

# Help Menu:
```
./exchange_hunter.py -h
usage: exchange_hunter.py [-h] [-d DOMAIN]

Exchange/Domain Controller Hunter for PrivExchange.

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target Domain.
```

ALSO:

Very much on the look out for better tactics on finding Exchange Servers in internal environments, so if you know any please share and help me write tools that will save everyone time and resources.
