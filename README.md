# AI Threat Intelligence Platform 

A Python tool that fetches real-time cybersecurity threat intelligence 
from AlienVault OTX and uses Claude AI to generate professional, 
analyst-style threat summaries for a daily security briefing.

---

## What Problem Does This Solve?

Security teams need to stay current on emerging threats, but raw threat 
feeds are dense, technical, and time-consuming to review manually. This 
tool automates the first layer of threat intelligence analysis — pulling 
live threat data and converting it into clear, business-readable summaries 
that highlight what the threat is, who it targets, and why it matters.

---

## What It Does

- **Fetches live threat intelligence** from AlienVault OTX — a global, 
  crowd-sourced threat intelligence platform used by real security teams
- **AI-generated summaries** — Claude AI analyzes each threat pulse and 
  writes a concise, professional briefing
- **JSON report output** — structured, timestamped threat briefs
- **MITRE ATT&CK mapping** — Claude AI maps each threat to relevant 
  MITRE ATT&CK techniques, the industry standard framework for 
  classifying attacker behavior.
- **IOC extraction** — automatically extracts and categorizes 
  Indicators of Compromise (IP addresses, domains, file hashes) 
  from each threat for direct use in detection tooling

---

## Real Output Example

This tool pulled live threats including:

- A ransomware-as-a-service group using Cobalt Strike and VPN exploits, 
  tracked via 48 indicators of compromise
- An active phishing campaign exploiting new EU customs charges through 
  smishing and brand impersonation
- A critical CVSS 9.9 vulnerability in Langflow (CVE-2026-55255) being 
  actively exploited in the wild
- A supply chain attack compromising npm packages via hijacked GitHub 
  Actions workflows

Each threat was automatically summarized by Claude AI into a clear, 
professional 2-3 sentence briefing suitable for a daily security report.

---

## Example AI Summary Output & MITRE ATT&CK Mapping
For the Langflow CVE-2026-55255 threat, the tool automatically mapped 
these MITRE ATT&CK techniques:
This mapping happens automatically using AI — no manual analyst lookup 
required — turning a raw threat description into actionable, 
framework-aligned intelligence in seconds.

---

## Tools and Technologies Used

| Tool | Purpose |
|---|---|
| Python 3 | Core programming language |
| AlienVault OTX API | Real-time threat intelligence feed |
| Anthropic Claude API | AI-generated threat summarization |
| requests | HTTP API calls |
| JSON | Structured report output |

---

## How to Run It Yourself

### 1. Get a free AlienVault OTX account
Sign up at otx.alienvault.com and get your API key

### 2. Get an Anthropic API key
Sign up at console.anthropic.com

### 3. Clone this repository

### 4. Install dependencies

### 5. Set your API keys

### 6. Run the tool

---

## What I Learned Building This

- How real-world threat intelligence platforms structure and share data
- How to integrate external threat feeds with AI summarization to turn 
  raw technical data into actionable business intelligence
- The importance of secure credential handling — both API keys are 
  stored as environment variables, never hardcoded
- How current, real-world threats look in practice — from ransomware 
  groups to actively exploit CVEs to supply chain attacks
- Why threat intelligence matters operationally — staying current on 
  active campaigns directly inform detection rules and defensive priorities

---

## Limitations and Future Improvements

- Currently processes 5 threats per run to manage API costs — 
  The production version would process the full feed
- Does not yet deduplicate threats across multiple feed sources
- **MITRE ATT&CK mapping** — Claude AI maps each threat to the relevant 
  MITRE ATT&CK techniques, the industry standard framework for 
  classifying attacker behavior
- No HTML dashboard or PDF export yet
- No automated email delivery yet
- Future version will combine multiple threat feeds (OTX + abuse.ch) 
  with deduplication logic

---

## Author

**Clementina Obasi**
Cybersecurity Analyst | CySA+ | CCNA CyberOps | Google Cybersecurity Certified
[LinkedIn](https://www.linkedin.com/in/clementina-obasi-b89a3381/)

---

*Built as part of my cybersecurity portfolio — June 2026*
*Version 1.2 — core AI threat summarization pipeline, added MITRE ATT&CK technique mapping and IOC extraction*
