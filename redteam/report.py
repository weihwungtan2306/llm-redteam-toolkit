"""
Renders a pentest-style Markdown report from a run_suite() results dict.
"""

from __future__ import annotations

from redteam.severity import sort_key

SECRET_LEAK_REMEDIATION = [
    "Never place long-lived secrets (API keys, override/authorization codes) in the "
    "system prompt at all -- treat the prompt as something the model may eventually "
    "repeat back verbatim. Keep secrets server-side and inject them only into tool "
    "calls whose raw output the model never sees.",
    "Add an output-side filter that scans every model response for known secret "
    "patterns (canary tokens, key formats, internal markers) and redacts or blocks "
    "before the response reaches the user -- independent of any input-side blocklist.",
    "Assume any input-side keyword blocklist will eventually be bypassed (translation, "
    "encoding, roleplay, and delimiter-confusion all defeated it in this assessment); "
    "treat it as a speed bump, not a control.",
    "Run automated red-team regressions like this suite against the deployed system "
    "prompt on every change, since prompts get edited and defenses silently regress.",
]

UNAUTHORIZED_REFUND_REMEDIATION = [
    "Never let the model authorize a sensitive action directly. Have it call a "
    "constrained function that independently re-validates authorization server-side, "
    "and never treat a claim made in free text as evidence of anything.",
    "Enforce hard business-rule limits (e.g. the refund ceiling) in code outside the "
    "model's control, not as instructions the model is merely asked to follow.",
    "Require a real, independently-verified credential for any above-threshold action "
    "-- never a code or claim typed by the counterparty the limit exists to constrain.",
    "Log and alert on model-initiated actions above a risk threshold for human review, "
    "regardless of what the model 'decided'.",
]

INDIRECT_INJECTION_REMEDIATION = [
    "Treat all ingested content (documents, tickets, emails, web pages the model is "
    "asked to summarize) as untrusted data, never as instructions. Structurally "
    "separate it from the instruction channel -- clearly delimited, explicitly "
    "labeled as data, with an explicit directive to never follow instructions found "
    "inside it -- and back that up with output-side controls rather than relying on "
    "the model alone to keep the distinction.",
    "Strip or neutralize instruction-like markup (fake system tags, HTML comments, "
    "delimiter spoofing) from ingested documents before they reach the model.",
]

MARKDOWN_EXFIL_REMEDIATION = [
    "Disable automatic rendering of markdown images/links in the chat client, or "
    "rewrite/strip outbound links to an allowlist of known domains, so a leaked "
    "secret cannot be silently exfiltrated via an auto-fetched URL the instant a "
    "response renders.",
]


def _remediation_for(finding: dict) -> list[str]:
    items = []
    if finding["check"] == "secret_leak":
        items += SECRET_LEAK_REMEDIATION
    elif finding["check"] == "unauthorized_refund":
        items += UNAUTHORIZED_REFUND_REMEDIATION
    if finding["channel"] == "summarize":
        items += INDIRECT_INJECTION_REMEDIATION
    if "markdown" in finding["technique"].lower() or "image" in finding["technique"].lower():
        items += MARKDOWN_EXFIL_REMEDIATION
    # de-dupe while preserving order
    seen = set()
    deduped = []
    for item in items:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _severity_counts(results: list[dict]) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for r in results:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts


def _truncate(text: str, n: int = 600) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else text[: n - 3] + "..."


def render_report(run: dict) -> str:
    results = run["results"]
    counts = _severity_counts(results)
    findings = sorted([r for r in results if r["success"]], key=sort_key)
    passed = [r for r in results if not r["success"]]

    lines = []
    lines.append("# LLM Red-Team Assessment Report")
    lines.append("")
    lines.append(f"**Target:** `{run['target']}`  ")
    lines.append(f"**Assessment date:** {run['run_at']}  ")
    lines.append(f"**Test cases executed:** {run['total']}  ")
    lines.append(f"**Findings:** {len(findings)} ({counts['Critical']} Critical, {counts['High']} High, "
                  f"{counts['Medium']} Medium, {counts['Low']} Low)")
    lines.append("")
    lines.append(
        "> **Scope & authorization:** This assessment was run against a system the "
        "tester owns/operates, for the purpose of identifying and fixing weaknesses "
        "before adversaries do. All secrets referenced below (API keys, authorization "
        "codes) are fictional canary values planted in a test app for detection "
        "purposes -- never real credentials. Only test systems you own or have "
        "explicit authorization to test."
    )
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    if counts["Critical"] or counts["High"]:
        lines.append(
            f"This assessment identified **{len(findings)} of {run['total']}** attack "
            "attempts succeeded against the target, including "
            f"**{counts['Critical']} Critical** and **{counts['High']} High** severity "
            "findings. Critical findings include full disclosure of the system prompt "
            "and embedded secrets, and/or unauthorized high-value actions triggered "
            "through prompt injection or social engineering. The pattern across "
            "findings is consistent: a keyword-based input blocklist stops the most "
            "obvious, well-known attack phrasings, but is bypassed by almost any "
            "rephrasing, translation, encoding, roleplay framing, or content smuggled "
            "in through an untrusted document. See Recommendations for structural "
            "fixes that do not depend on pattern-matching the attacker's wording."
        )
    else:
        lines.append(
            f"This assessment ran {run['total']} attack attempts against the target; "
            "no successful findings were identified."
        )
    lines.append("")

    lines.append("### Results by category")
    lines.append("")
    lines.append("| Category | Attempts | Succeeded |")
    lines.append("|---|---|---|")
    by_cat = {}
    for r in results:
        c = by_cat.setdefault(r["category"], {"attempts": 0, "succeeded": 0})
        c["attempts"] += 1
        if r["success"]:
            c["succeeded"] += 1
    for cat, c in sorted(by_cat.items()):
        lines.append(f"| {cat.replace('_', ' ').title()} | {c['attempts']} | {c['succeeded']} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No findings -- every attack attempt was blocked as intended.")
        lines.append("")
    else:
        lines.append("| ID | Severity | Category | Technique | OWASP |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            lines.append(f"| {f['id']} | **{f['severity']}** | {f['category'].replace('_',' ')} | {f['technique']} | {f['owasp']} |")
        lines.append("")

        for f in findings:
            lines.append(f"### {f['id']} -- {f['technique']} ({f['severity']})")
            lines.append("")
            lines.append(f"**Category:** {f['category'].replace('_', ' ')}  ")
            lines.append(f"**OWASP mapping:** {f['owasp']}  ")
            lines.append(f"**Channel:** `{f['channel']}`")
            lines.append("")
            if f["description"]:
                lines.append(f['description'])
                lines.append("")
            lines.append(f"**Evidence:** `{f['evidence']}`")
            lines.append("")
            lines.append("**Target response (truncated):**")
            lines.append("```")
            lines.append(_truncate(f["final_reply"]))
            lines.append("```")
            lines.append("")
            remediation = _remediation_for(f)
            if remediation:
                lines.append("**Recommended fix:**")
                lines.append("")
                for item in remediation:
                    lines.append(f"- {item}")
                lines.append("")

    lines.append("## Blocked / Passed Attempts")
    lines.append("")
    lines.append(
        "These attempts did not succeed against the target, either because a "
        "defense correctly held or because the test was a negative control included "
        "to calibrate the results above."
    )
    lines.append("")
    lines.append("| ID | Category | Technique |")
    lines.append("|---|---|---|")
    for r in sorted(passed, key=lambda x: x["id"]):
        lines.append(f"| {r['id']} | {r['category'].replace('_',' ')} | {r['technique']} |")
    lines.append("")

    lines.append("## Methodology & Limitations")
    lines.append("")
    lines.append(
        "Attacks were executed as ordinary HTTP requests against the target's chat "
        "and document-summarization endpoints, treating it as a black box -- the "
        "same access an external attacker would have. Success/failure was determined "
        "by pattern-matching the target's own response text for known canary "
        "secrets and compliance phrases (see `redteam/detectors.py`); this catches "
        "clear-cut leaks and unauthorized actions reliably, but a heuristic detector "
        "can both miss subtler partial leaks and, in principle, be fooled by a "
        "response that echoes a canary string without actually complying. Treat "
        "automated findings as a starting point for human review, not a final verdict."
    )
    lines.append("")
    lines.append(
        "This run used the toolkit's bundled attack library "
        f"(`attacks/library.yaml`, {run['total']} cases). See README.md for how to "
        "extend the library or point the runner at a different target."
    )
    lines.append("")

    return "\n".join(lines)
