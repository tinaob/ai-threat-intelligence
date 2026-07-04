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
# HTML DASHBOARD
# ============================================
def generate_html_dashboard(threats):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    threat_cards = ""
    for threat in threats:
        # Build IOC section
        iocs = threat.get('iocs', {})
        ioc_html = ""

        if iocs.get('ip_addresses'):
            ips = '</code> <code>'.join(iocs['ip_addresses'][:5])
            ioc_html += f'<div class="ioc-group"><span class="ioc-label">🌐 IPs:</span> <code>{ips}</code></div>'

        if iocs.get('domains'):
            domains = '</code> <code>'.join(iocs['domains'][:5])
            ioc_html += f'<div class="ioc-group"><span class="ioc-label">🔗 Domains:</span> <code>{domains}</code></div>'

        if iocs.get('file_hashes'):
            hashes = '<br>'.join(iocs['file_hashes'][:3])
            ioc_html += f'<div class="ioc-group"><span class="ioc-label">🗂️ Hashes:</span><br><code>{hashes}</code></div>'

        if not ioc_html:
            ioc_html = '<div class="ioc-group">No IOCs extracted</div>'

        # Build MITRE techniques section
        mitre_html = ""
        techniques = threat.get('mitre_techniques', [])
        if techniques:
            for technique in techniques:
                parts = technique.split(' - ', 1)
                if len(parts) == 2:
                    tid, tname = parts
                    mitre_html += f'<span class="mitre-badge">{tid} — {tname}</span>'
        else:
            mitre_html = '<span class="mitre-badge">Not mapped</span>'

        # Build tags
        tags_html = ' '.join([
            f'<span class="tag">{tag}</span>'
            for tag in threat.get('tags', [])[:5]
        ])

        # AI summary
        summary = threat.get('ai_summary', 'No summary available')
        summary = summary.replace('**', '').replace('*', '')

        threat_cards += f"""
        <div class="threat-card">
            <div class="threat-header">
                <h3>🚨 {threat['name']}</h3>
                <span class="indicator-count">{threat['indicator_count']} indicators</span>
            </div>
            <div class="tags">{tags_html}</div>

            <div class="section">
                <h4>🤖 AI Summary</h4>
                <p class="summary">{summary}</p>
            </div>

            <div class="section">
                <h4>🎯 MITRE ATT&CK Techniques</h4>
                <div class="mitre-container">{mitre_html}</div>
            </div>

            <div class="section">
                <h4>🔍 Indicators of Compromise</h4>
                <div class="ioc-container">{ioc_html}</div>
            </div>
        </div>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI Threat Intelligence Daily Brief</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #0a0e1a;
            color: #e0e6f0;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1f35, #2d3561);
            border: 1px solid #3d4a7a;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 28px;
            color: #60a5fa;
            margin-bottom: 8px;
        }}
        .header p {{
            color: #94a3b8;
            font-size: 14px;
        }}
        .stats-bar {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            background: #1a1f35;
            border: 1px solid #3d4a7a;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            color: #60a5fa;
        }}
        .stat-label {{
            font-size: 13px;
            color: #94a3b8;
            margin-top: 5px;
        }}
        .threat-card {{
            background: #1a1f35;
            border: 1px solid #3d4a7a;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            transition: border-color 0.2s;
        }}
        .threat-card:hover {{
            border-color: #60a5fa;
        }}
        .threat-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }}
        .threat-header h3 {{
            font-size: 16px;
            color: #f87171;
            flex: 1;
            margin-right: 15px;
        }}
        .indicator-count {{
            background: #2d3561;
            color: #60a5fa;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            white-space: nowrap;
        }}
        .tags {{
            margin-bottom: 15px;
        }}
        .tag {{
            background: #2d3561;
            color: #94a3b8;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            margin-right: 5px;
            margin-bottom: 5px;
            display: inline-block;
        }}
        .section {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #2d3561;
        }}
        .section h4 {{
            font-size: 13px;
            color: #60a5fa;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .summary {{
            font-size: 14px;
            line-height: 1.6;
            color: #cbd5e1;
        }}
        .mitre-container {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .mitre-badge {{
            background: #1e3a5f;
            border: 1px solid #2563eb;
            color: #93c5fd;
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-family: monospace;
        }}
        .ioc-container {{
            font-size: 13px;
        }}
        .ioc-group {{
            margin-bottom: 8px;
        }}
        .ioc-label {{
            color: #94a3b8;
            font-size: 12px;
            margin-right: 5px;
        }}
        code {{
            background: #0f172a;
            color: #34d399;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            font-family: monospace;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #475569;
            font-size: 12px;
            border-top: 1px solid #1e293b;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI Threat Intelligence Daily Brief</h1>
        <p>Generated: {timestamp} | Powered by AlienVault OTX + Claude AI</p>
        <p>Built by Clementina Obasi — Cybersecurity Portfolio Project</p>
    </div>

    <div class="stats-bar">
        <div class="stat-card">
            <div class="stat-number">{len(threats)}</div>
            <div class="stat-label">Threats Analyzed</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{sum(t['indicator_count'] for t in threats)}</div>
            <div class="stat-label">Total Indicators</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{sum(len(t.get('mitre_techniques', [])) for t in threats)}</div>
            <div class="stat-label">MITRE Techniques Mapped</div>
        </div>
    </div>

    {threat_cards}

    <div class="footer">
        <p>AI Threat Intelligence Platform v2.0 | 
        Built by Clementina Obasi | 
        github.com/tinaob/ai-threat-intelligence</p>
    </div>
</body>
</html>
    """

    filename = f"threat_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"🌐 HTML Dashboard saved to: {filename}")
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
    generate_html_dashboard(threats)

    print("\n" + "=" * 60)
    print("   THREAT BRIEF COMPLETE")
    print("=" * 60 + "\n")

main()