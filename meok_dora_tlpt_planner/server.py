"""meok-dora-tlpt-planner-mcp — DORA Article 26 Threat-Led Penetration Testing planner

Operationalises the TIBER-EU pathway for in-scope financial entities under DORA
Regulation (EU) 2022/2554 Articles 26-27. Generates scoping documents, white-team
RACI matrices, threat intelligence templates, and HMAC-signed compliance attestations
verifiable via meok-attestation-api.

By MEOK AI Labs (https://meok.ai). MIT licensed.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("meok-dora-tlpt-planner")

# === Constants ===

ATTESTATION_API = os.environ.get("MEOK_ATTESTATION_API", "https://meok-attestation-api.vercel.app")

# DORA Article 26-27 + TIBER-EU pathway phases (per ECB TIBER-EU framework v2.0 + DORA RTS on TLPT)
TIBER_PHASES = {
    "preparation": {
        "duration_weeks": "4-8",
        "description": "Scope definition, white-team assembly, threat-intel commission",
        "deliverables": [
            "TLPT scope document (critical/important functions selected)",
            "White-team Terms of Reference (ToR)",
            "Threat-intelligence provider engagement letter",
            "Red-team provider qualification (DORA Art. 27 RTS)",
            "Notification to lead overseer (TIBER-EU Cyber Team / national authority)",
        ],
        "stakeholders": ["white-team-lead", "ciso", "head-of-it-risk", "tlpt-cyber-team"],
    },
    "testing": {
        "duration_weeks": "12-16",
        "description": "Threat intelligence + red-team engagement against live production",
        "deliverables": [
            "Targeted Threat Intelligence (TTI) report",
            "Red-team Test Plan (TTP-mapped to MITRE ATT&CK)",
            "Live red-team engagement against production systems",
            "Daily situation reports to white-team",
            "Test summary findings report",
        ],
        "stakeholders": ["red-team", "threat-intel-provider", "white-team-lead"],
    },
    "closure": {
        "duration_weeks": "6-10",
        "description": "Findings, remediation, replay, attestation",
        "deliverables": [
            "Findings report with severity-ranked detected gaps",
            "Remediation plan (90/180/365-day milestones)",
            "Purple-team replay test (validate fixes)",
            "Final TLPT attestation (signed by white-team + RT lead)",
            "Submission to lead overseer for sign-off (Art. 26(7) DORA)",
        ],
        "stakeholders": ["white-team-lead", "remediation-owner", "lead-overseer"],
    },
}

# DORA Article 27 — Red-team provider requirements (per RTS on TLPT)
RT_PROVIDER_REQUIREMENTS = [
    "Independent from the financial entity (no commercial conflict in last 24 months)",
    "Hold ISO/IEC 27001 + ISO/IEC 27037 certifications",
    "Minimum 5 years of red-team engagements in financial sector",
    "Per Art. 27(2): qualified personnel with documented competence in MITRE ATT&CK",
    "Civil liability insurance ≥€10M",
    "GDPR-compliant data handling for any captured live data",
    "Background-checked staff for engagements above EUR 1B in critical functions",
]

# White-team RACI roles (per TIBER-EU framework)
WHITE_TEAM_RACI = {
    "white-team-lead": {
        "responsibility": "Overall test integrity + safety; sole authority to abort/pause test",
        "accountability": "Reports directly to CEO/CISO; signs final attestation",
    },
    "operations-coordinator": {
        "responsibility": "Real-time situation awareness during red-team engagement; SOC-liaison",
        "accountability": "Briefs white-team-lead twice daily during testing phase",
    },
    "evidence-custodian": {
        "responsibility": "Cryptographic chain-of-custody for all findings, screenshots, packet captures",
        "accountability": "Maintains tamper-evident artifact log; produces signed evidence pack at closure",
    },
    "remediation-owner": {
        "responsibility": "Tracks remediation tickets to closure; coordinates purple-team replay",
        "accountability": "Reports to CTO/CISO; produces 90/180/365-day milestone reports",
    },
    "comms-lead": {
        "responsibility": "Internal stakeholder communication; ensures NO leak of test status to blue-team",
        "accountability": "Reports to white-team-lead; signs comms-discipline attestation",
    },
}

# Threat-intelligence template fields (per ECB TIBER-EU v2.0)
TTI_FIELDS = [
    "Entity profile (sector, size, geographic footprint, critical functions)",
    "Threat actor selection (1-2 nation-state + 1-2 financially-motivated, justified per current threat landscape)",
    "TTPs per threat actor (mapped to MITRE ATT&CK Enterprise + ICS)",
    "Initial access vectors (phishing, supply-chain, vendor compromise, etc.)",
    "Data exfiltration scenarios (customer data, transaction records, IP)",
    "Disruption scenarios (ransomware, wiper, market manipulation)",
    "Evidence sources cited (MISP feeds, vendor reports, government advisories)",
    "Attribution confidence (HIGH/MEDIUM/LOW per ICD-203)",
]

# === Tools ===


@mcp.tool()
def scope_tlpt(
    entity_name: str,
    entity_type: str,
    sector: str = "credit-institution",
    critical_functions: list[str] | None = None,
    last_tlpt_date: str | None = None,
    annual_budget_estimate_eur: int | None = None,
) -> dict[str, Any]:
    """Generate a DORA Article 26 TLPT scope document for a financial entity.

    Args:
        entity_name: Legal name of the financial entity (e.g., "Acme Bank N.V.").
        entity_type: One of credit-institution / investment-firm / insurance / pension-fund /
            payment-institution / e-money-institution / market-infrastructure / CCP.
        sector: ISIC sector code (default: credit-institution).
        critical_functions: List of critical/important functions to be scoped (per Art. 26(2)).
            E.g., ["retail-payments", "trading-platform", "customer-onboarding"].
        last_tlpt_date: ISO date of last TLPT (YYYY-MM-DD) — DORA mandates 3-year cycle.
        annual_budget_estimate_eur: Estimated TLPT engagement budget (drives RT-provider tier).

    Returns:
        Structured scope document with phase plan, deliverables, RACI, and budget breakdown.
    """
    critical_functions = critical_functions or ["retail-payments", "core-banking"]
    today = datetime.now(timezone.utc).date().isoformat()

    # Cycle math: DORA Art. 26(1)(b) — TLPT every 3 years for significant/systemic FIs
    next_tlpt_due = "TBD"
    if last_tlpt_date:
        try:
            last = datetime.fromisoformat(last_tlpt_date).date()
            next_tlpt_due = last.replace(year=last.year + 3).isoformat()
        except ValueError:
            next_tlpt_due = "INVALID_DATE_FORMAT"

    # Budget tiering (rough; final RT-provider quotes vary)
    if annual_budget_estimate_eur is None:
        budget_tier = "UNKNOWN"
    elif annual_budget_estimate_eur < 100_000:
        budget_tier = "INSUFFICIENT — DORA TLPT typically EUR 250-500K minimum"
    elif annual_budget_estimate_eur < 500_000:
        budget_tier = "TIER-3 (mid-cap FI)"
    elif annual_budget_estimate_eur < 2_000_000:
        budget_tier = "TIER-2 (large FI)"
    else:
        budget_tier = "TIER-1 (G-SIB)"

    return {
        "entity": {
            "name": entity_name,
            "type": entity_type,
            "sector": sector,
        },
        "scope": {
            "critical_functions_in_scope": critical_functions,
            "exclusions_to_document": [
                "Functions outside DORA Art. 6(8) operational risk perimeter",
                "Sandbox/test environments not used by customers",
                "Functions covered by parent-level group TLPT in last 12 months",
            ],
        },
        "cycle": {
            "last_tlpt_date": last_tlpt_date,
            "next_tlpt_due": next_tlpt_due,
            "cycle_basis": "DORA Art. 26(1)(b) — significant/systemic FIs every 3 years",
        },
        "phases": TIBER_PHASES,
        "white_team_raci": WHITE_TEAM_RACI,
        "rt_provider_requirements": RT_PROVIDER_REQUIREMENTS,
        "budget": {
            "estimate_eur": annual_budget_estimate_eur,
            "tier": budget_tier,
            "breakdown_typical": {
                "threat_intelligence_eur": "30000-80000",
                "red_team_eur": "100000-500000",
                "white_team_internal_eur": "60000-200000 (FTE-equivalent)",
                "remediation_reserve_eur": "100000-500000 (post-test)",
            },
        },
        "scope_document_metadata": {
            "drafted_on": today,
            "drafted_by_tool": "meok-dora-tlpt-planner-mcp",
            "tool_version": "1.0.0",
        },
    }


@mcp.tool()
def threat_intel_brief(
    entity_name: str,
    entity_sector: str,
    geographic_footprint: list[str],
    critical_functions: list[str],
) -> dict[str, Any]:
    """Generate a Targeted Threat Intelligence (TTI) brief template per ECB TIBER-EU v2.0.

    This is a SCAFFOLD. Real TTI must be authored by an accredited threat-intel
    provider with current intelligence feeds. Use this template to brief them.

    Args:
        entity_name: Legal name of the financial entity.
        entity_sector: One of retail-banking, wholesale-banking, insurance, asset-management,
            market-infrastructure, payments, e-money.
        geographic_footprint: List of country codes where entity operates (e.g., ["DE", "NL", "IE"]).
        critical_functions: List of critical functions for which threats must be modelled.

    Returns:
        TTI template with sections aligned to TIBER-EU + ECB standards.
    """
    return {
        "tti_brief_type": "DORA Art. 26 / TIBER-EU v2.0 compliant scaffold",
        "entity_profile": {
            "name": entity_name,
            "sector": entity_sector,
            "geographic_footprint": geographic_footprint,
            "critical_functions": critical_functions,
        },
        "required_sections": TTI_FIELDS,
        "minimum_threat_actor_count": 3,
        "threat_actor_selection_rationale": [
            "At least 1 nation-state actor relevant to entity geography (e.g., APT28, Lazarus)",
            "At least 1 financially-motivated group (e.g., FIN7, Cl0p, BlackBasta)",
            "Optionally 1 hacktivist or insider-threat scenario for completeness",
            "Justify each selection with current threat-landscape evidence (last 6 months)",
        ],
        "delivery_requirements": {
            "format": "PDF + machine-readable JSON (STIX 2.1 preferred)",
            "page_count_typical": "60-120 pages",
            "delivery_to": "white-team-lead only (NEVER to red-team direct, NEVER to blue-team)",
            "retention_post_test": "7 years per DORA Art. 14",
        },
        "downstream_use": [
            "Red-team uses TTPs from TTI to drive engagement plan",
            "White-team uses TTI to validate test realism",
            "Lead overseer reviews TTI as part of test scope approval (Art. 26(7))",
        ],
    }


@mcp.tool()
def remediation_milestones(findings_count: int, severity_distribution: dict[str, int]) -> dict[str, Any]:
    """Generate a 90/180/365-day remediation milestone plan based on TLPT findings.

    Args:
        findings_count: Total number of findings from the red-team report.
        severity_distribution: Dict with keys 'critical', 'high', 'medium', 'low' and counts.

    Returns:
        Milestone plan with required closure timelines per severity.
    """
    sev = {**{"critical": 0, "high": 0, "medium": 0, "low": 0}, **severity_distribution}
    total = sev["critical"] + sev["high"] + sev["medium"] + sev["low"]
    if total != findings_count:
        return {
            "error": f"severity_distribution sum ({total}) != findings_count ({findings_count})",
        }

    return {
        "milestones": {
            "30_days": {
                "scope": f"All {sev['critical']} CRITICAL findings closed or compensating controls deployed",
                "evidence_required": "Per-finding remediation ticket with code-change PR or config-change record",
            },
            "90_days": {
                "scope": f"All {sev['high']} HIGH findings closed; {sev['medium'] // 2} MEDIUM remediation in flight",
                "evidence_required": "Purple-team replay test confirms CRITICAL+HIGH closures",
            },
            "180_days": {
                "scope": f"All {sev['medium']} MEDIUM findings closed; {sev['low'] // 2} LOW remediation in flight",
                "evidence_required": "Updated control framework reflecting structural fixes",
            },
            "365_days": {
                "scope": f"All {sev['low']} LOW findings closed or formally accepted with risk-owner sign-off",
                "evidence_required": "Final remediation pack signed by CRO + CISO; ready for next-cycle TLPT",
            },
        },
        "total_findings": findings_count,
        "severity_distribution": sev,
        "regulatory_basis": "DORA Art. 26(7) — remediation closure required before next TLPT cycle",
    }


@mcp.tool()
def signed_tlpt_attestation(
    entity_name: str,
    scope_summary: str,
    test_phase: str,
    findings_summary: dict[str, Any],
    signing_role: str = "white-team-lead",
) -> dict[str, Any]:
    """Produce an HMAC-signed TLPT attestation via the public meok-attestation-api.

    Args:
        entity_name: Legal name of the financial entity.
        scope_summary: 1-3 sentence summary of test scope.
        test_phase: One of preparation / testing / closure.
        findings_summary: Dict with findings_count, severity_distribution, and summary text.
        signing_role: Role of the signer (default white-team-lead).

    Returns:
        Signed attestation with verification URL.
    """
    payload = {
        "kind": "dora-tlpt-attestation",
        "entity": entity_name,
        "scope": scope_summary,
        "phase": test_phase,
        "findings": findings_summary,
        "signing_role": signing_role,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "regulatory_basis": "DORA Reg (EU) 2022/2554 Art. 26-27 + TIBER-EU v2.0",
        "tool": "meok-dora-tlpt-planner-mcp",
        "tool_version": "1.0.0",
    }

    try:
        req = urllib.request.Request(
            f"{ATTESTATION_API}/sign",
            data=json.dumps({"payload": payload, "type": "dora-tlpt"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        return {
            "ok": True,
            "payload": payload,
            "signature": result.get("signature"),
            "verify_url": result.get("verify_url"),
            "attestation_id": result.get("attestation_id"),
        }
    except urllib.error.URLError as e:
        return {
            "ok": False,
            "error": f"attestation API unreachable: {e}",
            "payload": payload,
            "fallback": "Use the payload above as a self-attestation; sign locally with your own HMAC key.",
        }


@mcp.tool()
def list_phases() -> dict[str, Any]:
    """List the 3 TIBER-EU TLPT phases with deliverables."""
    return TIBER_PHASES


@mcp.tool()
def pricing() -> dict[str, Any]:
    """Pricing for MEOK DORA TLPT Planner."""
    return {
        "free_tier": {
            "price": "£0",
            "features": [
                "All scope/TTI/remediation tools above",
                "Public attestation API (shared HMAC issuer)",
                "MIT-licensed source code",
            ],
        },
        "pro": {
            "price": "£79/mo",
            "features": [
                "Free tier + your own HMAC signing key",
                "Custom attestation domain (your-firm.com/verify)",
                "Email support",
            ],
        },
        "enterprise": {
            "price": "£1,499/mo",
            "features": [
                "Pro tier + multi-BU separation for group-level TLPT coordination",
                "SLA on attestation API (99.9%)",
                "Direct slack/teams support channel",
                "White-label for resellers (consultancies)",
            ],
            "fit": "Significant/systemic financial entities with concurrent TLPT engagements across BUs",
        },
        "bespoke": {
            "price": "from £5,000",
            "features": [
                "Self-hosted attestation API on your infrastructure",
                "Custom integrations with GRC stack (Archer, ServiceNow, etc.)",
                "On-site white-team training (2 days)",
            ],
        },
        "purchase": "https://meok.ai/pricing",
        "contact": "nicholas@csoai.org",
    }


if __name__ == "__main__":
    mcp.run()
