# meok-dora-tlpt-planner-mcp

[![PyPI](https://img.shields.io/pypi/v/meok-dora-tlpt-planner-mcp.svg)](https://pypi.org/project/meok-dora-tlpt-planner-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-server-purple)](https://modelcontextprotocol.io)

> DORA Article 26 Threat-Led Penetration Testing (TLPT) planner — TIBER-EU pathway scoping, white-team RACI, threat-intel briefing templates, and HMAC-signed compliance attestations.

**By [MEOK AI Labs](https://meok.ai)** · MIT licensed · runs as an [MCP server](https://modelcontextprotocol.io) inside Claude Code, Cursor, Cline, Windsurf, etc.

---

## Why this exists

DORA Reg (EU) 2022/2554 Articles 26-27 require significant/systemic financial entities to conduct Threat-Led Penetration Testing (TLPT) every three years using accredited red-team providers and following the TIBER-EU framework.

Today, **TLPT engagements cost €250-500K minimum** (€30-80K threat-intel report + €100-500K red-team + €100-500K remediation reserve). Sub-significant institutions wanting to look ready for a regulator visit have no entry-level path.

This MCP gives you the **scoping + planning layer for free**, MIT-licensed, callable from any AI agent, with HMAC-signed attestations the regulator can verify cryptographically.

It does **not** replace an accredited red-team provider. It compresses the planning + RACI + remediation tracking phases that today eat 30-40% of TLPT consulting fees.

## Tools

| Tool | Use |
|---|---|
| `scope_tlpt` | Generate a DORA Art. 26 scope document with phase plan, RACI, RT-provider requirements, budget tiering |
| `threat_intel_brief` | Produce a TIBER-EU v2.0-compliant TTI brief template to commission accredited threat-intel providers |
| `remediation_milestones` | 90/180/365-day remediation plan with severity-mapped closure timelines (Art. 26(7)) |
| `signed_tlpt_attestation` | HMAC-sign your TLPT attestation via `meok-attestation-api`; produces verification URL |
| `list_phases` | List the 3 TIBER-EU phases (preparation/testing/closure) with deliverables |
| `pricing` | Pricing tiers (free / £79 Pro / £1,499 Enterprise / from £5K bespoke) |

## Install

```bash
pip install meok-dora-tlpt-planner-mcp
```

Then add to your Claude Code / Cursor / Cline MCP config:

```json
{
  "mcpServers": {
    "meok-dora-tlpt-planner": {
      "command": "python",
      "args": ["-m", "meok_dora_tlpt_planner"]
    }
  }
}
```

## Example use

Inside Claude Code:

> "Scope a DORA TLPT for Acme Bank N.V., a credit institution operating in DE, NL, IE. Critical functions: retail-payments, core-banking, customer-onboarding. Last TLPT was 2023-06-15. Annual budget estimate €750K."

Claude calls `scope_tlpt(...)`, returns a structured scope doc with phase plan, RACI, RT-provider requirements, and budget tiering. You review, correct, sign with `signed_tlpt_attestation()`, hand to your white-team-lead.

> "Generate the 90/180/365 remediation milestone plan for 47 findings: 3 critical, 11 high, 23 medium, 10 low."

Claude returns a structured milestone plan with severity-mapped closure timelines per DORA Art. 26(7).

## Compliance posture

- **DORA Reg (EU) 2022/2554** Art. 26-27 (TLPT)
- **DORA RTS on TLPT** (per Art. 26(11) — final RTS adopted 2024)
- **TIBER-EU framework v2.0** (ECB, August 2023 update)
- **MITRE ATT&CK** Enterprise + ICS (for TTP mapping in TTI briefs)
- **ICD-203** standard for attribution confidence statements

## Pricing

- **Free** — full toolset, public attestation API (shared HMAC issuer)
- **£79/mo Pro** — your own HMAC signing key + custom verify domain
- **£1,499/mo Enterprise** — multi-BU separation for group-level coordination + SLA
- **from £5,000 bespoke** — self-hosted attestation API + GRC integrations + on-site training

Buy: https://meok.ai/pricing · Contact: nicholas@csoai.org

## Reseller / consultancy partnership

If you're a Big 4 / boutique consultancy running TLPT engagements, MEOK has a 70/30 reseller split for the Pro tier. White-label it for your clients. Email nicholas@csoai.org with subject "TLPT reseller inquiry".

## License

MIT. © 2026 Nicholas Templeman / CSOAI LTD (UK Companies House 16939677).

## See also

- [meok-dora-compliance-mcp](https://github.com/CSOAI-ORG/dora-compliance-mcp) — broader DORA compliance toolkit (Art. 28 register, Art. 18 incident reporting)
- [meok-attestation-api](https://meok-attestation-api.vercel.app/health) — public verifiable attestation infrastructure
- [Full MEOK fleet](https://github.com/CSOAI-ORG)
