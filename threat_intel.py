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

    for pulse in pulses[:5]:  # limit to 5 for now to save API credits
        name = pulse.get('name', 'Unknown')
        description = pulse.get('description', 'No description available')
        created = pulse.get('created', 'Unknown date')
        tags = pulse.get('tags', [])
        indicator_count = len(pulse.get('indicators', []))

        threats.append({
            "name": name,
            "description": description[:300],
            "created": created,
            "tags": tags,
            "indicator_count": indicator_count
        })

        print(f"📌 {name}")
        print(f"   Indicators: {indicator_count} | Tags: {', '.join(tags[:5])}\n")

    return threats

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
    print("GENERATING AI SUMMARIES...")
    print("=" * 60)

    for threat in threats:
        print(f"💡 Summarizing: {threat['name']}...")
        summary = summarize_with_ai(threat)
        threat['ai_summary'] = summary
        print(f"   {summary}\n")

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