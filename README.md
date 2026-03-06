# pi-recon

Security reconnaissance toolkit for pi. Redteam/pentest from the terminal.

## Commands

| Command | Description |
|---------|-------------|
| `/recon target.com` | Full recon (all checks) |
| `/recon headers target.com` | Security headers audit (HSTS, CSP, etc) |
| `/recon ssl target.com` | SSL/TLS certificate check |
| `/recon dns target.com` | DNS records (A, AAAA, MX, NS, TXT) |
| `/recon ports target.com` | Common port scan (18 ports) |
| `/recon tech target.com` | Technology fingerprinting |
| `/recon crawl target.com` | Path discovery (robots.txt, sensitive files) |

## Features
- Security header grading (A-F)
- Sensitive file detection (config leaks, exposed debug endpoints)
- Tech stack fingerprinting (React, Next.js, WordPress, etc)
- robots.txt disallowed paths extraction
- Also available as LLM tool (security_recon)
