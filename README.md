# pydig

DNSへの問い合わせ習作

```
$ ./main.py github.com
# HEADER
ID      QR        OPCODE  AA      TC             RD                     RA      RCODE     QD      AN      NS      AR
20730   Response  Query   No      Not truncated  Full service resolver  No      No error  1       1       0       0

Domain: github.com

# ANSWER SECTION
TYPE    CLASS   TTL     IP_OR_FQDN
A       IN      7       13.114.40.48
```
