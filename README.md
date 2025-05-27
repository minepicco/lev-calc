# levcalc

Vibe-coded LEV (Likely Exploitable Vulnerability) Calculator

https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf

100% vibe-coded, one shot


```
$ go build ./main.go
$ ./main -cves CVE-2024-26198
LEVCalc: 2025/05/27 16:56:50.932791 Info: -d0 flag not set, defaulting to 2025-02-26 (90 days before dn 2025-05-27)
LEVCalc: 2025/05/27 16:56:50.932906 Starting LEV calculation for 1 CVE(s)...
LEVCalc: 2025/05/27 16:56:50.932912 Processing CVE: CVE-2024-26198 (d0: 2025-02-26, dn: 2025-05-27)
LEVCalc: 2025/05/27 16:56:57.300831 LEV for CVE-2024-26198 (d0=2025-02-26, dn=2025-05-27): 0.6722. Scanned 91 days, 91 API calls for this CVE. Time: 6.36791s
LEVCalc: 2025/05/27 16:56:57.300897 Finished processing all CVEs. Total API calls: 91. Total time: 6.367984208s
```
