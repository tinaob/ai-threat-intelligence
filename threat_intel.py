import requests
import json
import os
import anthropic
from datetime import datetime

# ============================================
# API KEYS — set these as environment variables
# OTX:        $env:OTX_API_KEY="your-key-here"
# ANTHROPIC:  $env:ANTHROPIC_API_KEY="your-key-here"
# ============================================
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ============================================
# STEP 1: Fetch threat feed from AlienVault OTX
# ============================================
def fetch_threat_feed():
    print("\n" + "=" * 60)
    print("   AI THREAT INTELLIGENCE PLATFORM v1.0")
    print("=" * 60)
    print("\n🌐 Fetching latest threat intelligence...\n")

    if not OTX_API_KEY:
        print("❌ OTX_API_KEY not set!")
        return []

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    try:
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code != 200:
            print(f"❌ API error: {response.status_code}")
            return []

        data = response.json()
        pulses = data.get('results', [])

        print(f"✅ Fetched {len(pulses)} threat intelligence pulses\n")
        return pulses

    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return []

# ============================================
# STEP 2: Extract key info from each pulse
# ============================================
def extract_threat_info(pulses):
    print("=" * 60)
    print("EXTRACTING THREAT DATA")
    print("=" * 60)

    threats = []

    for pulse in pulses[:5]:
        name = pulse.get('name', 'Unknown')
        description = pulse.get('description', 'No description available')
        created = pulse.get('created', 'Unknown date')
        tags = pulse.get('tags', [])
        raw_indicators = pulse.get('indicators', [])

        # Extract and categorize IOCs by type
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "file_hashes": [],
            "other": []
        }

        for indicator in raw_indicators:
            ind_type = indicator.get('type', '')
            ind_value = indicator.get('indicator', '')

            if not ind_value:
                continue

            if ind_type in ['IPv4', 'IPv6']:
                iocs['ip_addresses'].append(ind_value)
            elif ind_type == 'domain' or ind_type == 'hostname':
                iocs['domains'].append(ind_value)
            elif ind_type == 'URL':
                iocs['urls'].append(ind_value)
            elif ind_type in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                iocs['file_hashes'].append(f"{ind_type}: {ind_value}")
            else:
                iocs['other'].append(f"{ind_type}: {ind_value}")

        # Limit each category to 5 examples to keep reports readable
        for key in iocs:
            iocs[key] = iocs[key][:5]

        total_iocs = sum(len(v) for v in iocs.values())

        threats.append({
            "name": name,
            "description": description[:300],
            "created": created,
            "tags": tags,
            "indicator_count": len(raw_indicators),
            "iocs": iocs,
            "total_iocs_extracted": total_iocs
        })

        print(f"📌 {name}")
        print(f"   Total Indicators: {len(raw_indicators)} | Tags: {', '.join(tags[:5])}")
        print(f"   IOCs extracted: {iocs['ip_addresses'][:2]} IPs, "
              f"{iocs['domains'][:2]} domains, {len(iocs['file_hashes'])} hashes\n")

    return threats
# ============================================
# MITRE ATT&CK MAPPING
# ============================================
def map_to_mitre_attack(threat):
    if not ANTHROPIC_API_KEY:
        return []

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

        prompt = f"""You are a MITRE ATT&CK mapping expert.

Threat Name: {threat['name']}
Description: {threat['description']}
Tags: {', '.join(threat['tags'])}

Based on this threat description, identify the 2-4 most relevant MITRE 
ATT&CK techniques. Respond ONLY in this exact format, one per line, 
nothing else:

T1190 - Exploit Public-Facing Application
T1078 - Valid Accounts

If you cannot confidently identify techniques, respond with:
No techniques identified

Do not add any explanation, preamble, or extra text."""

        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=150,
            messages=[{"role": "user", "content": prompt}]
        )

        response_text = message.content[0].text.strip()

        if "No techniques identified" in response_text:
            return []

        techniques = [line.strip() for line in response_text.split('\n') if line.strip()]
        return techniques

    except Exception as e:
        return [f"MITRE mapping unavailable: {str(e)[:50]}"]
# ============================================
# STEP 3: Use AI to summarize each threat
# ============================================
def summarize_with_ai(threat):
    if not ANTHROPIC_API_KEY:
        return "AI summary unavailable — API key not set"

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

        prompt = f"""You are a cybersecurity threat intelligence analyst.

Threat Name: {threat['name']}
Description: {threat['description']}
Tags: {', '.join(threat['tags'])}
Number of Indicators: {threat['indicator_count']}

Write a concise 2-3 sentence summary for a daily security briefing covering:
1. What this threat is
2. Who or what it targets
3. Why a security team should care

Keep it clear and professional. No bullet points."""

        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=150,
            messages=[{"role": "user", "content": prompt}]
        )

        return message.content[0].text

    except Exception as e:
        return f"AI summary unavailable: {str(e)[:50]}"

# ============================================
# STEP 4: Generate the daily brief
# ============================================
def generate_daily_brief(threats):
    print("=" * 60)
    print("GENERATING AI SUMMARIES & MITRE MAPPING...")
    print("=" * 60)

    for threat in threats:
        print(f"💡 Summarizing: {threat['name']}...")
        summary = summarize_with_ai(threat)
        threat['ai_summary'] = summary
        print(f"   {summary}\n")

        print(f"🎯 Mapping to MITRE ATT&CK...")
        techniques = map_to_mitre_attack(threat)
        threat['mitre_techniques'] = techniques
        if techniques:
            for t in techniques:
                print(f"   {t}")
        else:
            print("   No specific techniques identified")
        print()

    return threats

# ============================================
# STEP 5: Save report
# ============================================
def save_report(threats):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"threat_brief_{timestamp}.json"

    with open(filename, 'w') as f:
        json.dump({
            "report_date": timestamp,
            "tool": "AI Threat Intelligence Platform v1.0",
            "total_threats": len(threats),
            "threats": threats
        }, f, indent=4)

    print(f"📄 Report saved to: {filename}")
    return filename

# ============================================
# MAIN: Run everything
# ============================================
def main():
    pulses = fetch_threat_feed()

    if not pulses:
        print("No threat data retrieved. Check your API key and connection.")
        return

    threats = extract_threat_info(pulses)
    threats = generate_daily_brief(threats)
    save_report(threats)

    print("\n" + "=" * 60)
    print("   THREAT BRIEF COMPLETE")
    print("=" * 60 + "\n")

main()