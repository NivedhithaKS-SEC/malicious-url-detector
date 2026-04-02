# Malicious URL Detector 🔍

**Nivedhitha KS | Cybersecurity Portfolio**

Analyses URLs for phishing, typosquatting, malware delivery, and 8 other threat indicators. Returns a 0–100 threat score with detailed findings.

## Live Demo
> [Add Render URL here after deployment](https://malicious-url-detector-azxn.onrender.com/)

## Detection Checks (11 total)
| Check | What It Catches |
|---|---|
| HTTPS enforcement | HTTP URLs passing credentials unencrypted |
| IP address host | Raw IPs used for malware C2 infrastructure |
| URL shorteners | Hidden destinations via bit.ly, tinyurl etc. |
| Suspicious TLDs | .tk .ml .xyz and 7 other high-risk TLDs |
| Typosquatting | Brand impersonation (paypal → paypall) |
| Phishing keywords | login, verify, suspended, confirm etc. |
| Excessive subdomains | secure.login.verify.attacker.com |
| Long URLs | Padding to obscure destination |
| @ symbol | http://google.com@evil.com trick |
| High path entropy | Random-looking paths in malware campaigns |
| Double extension | invoice.pdf.exe malware delivery |

## Live Demo : https://malicious-url-detector-azxn.onrender.com/
```

## About
> "I built a URL threat analyser that runs 11 detection checks including typosquatting detection, entropy analysis, and homoglyph checks. It scores URLs from 0–100 and returns categorised findings with explanations. Built with Python and Flask."
