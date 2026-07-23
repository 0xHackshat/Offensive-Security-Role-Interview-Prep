Other Questions 
---

**Q1. How would you run day-to-day bug bounty program operations?**
- Own triage queue on managed platform (Bugcrowd/HackerOne) — first-response SLA, severity SLA, resolution SLA
- Triage flow: reproduce → validate → classify (CVSS/OWASP) → assign priority → route to eng
- Payout decisions tied to severity + program reward table, not researcher's self-assessed severity
- Track SLA compliance metrics weekly; flag backlog risk before it breaches
- Balance volume (informational/duplicate/N/A reports) vs. genuine criticals — triage queue is a funnel, not a ticket dump

**Q2. How do you validate a report without trusting the researcher's repro steps?**
- Independently re-derive: what trust boundary is crossed, what data flows where
- Ask: does this work only under researcher's specific conditions, or generally exploitable?
- Distinguish "weakness present" vs. "confirmed exploitability" (your own framing principle)
- Extend/chain the finding yourself — try adjacent endpoints, other roles, other tenants
- Theoretical severity ≠ real risk — down/upgrade CVSS based on actual business context, not CVSS calculator alone

**Q3. How do you handle researcher relations and disputes?**
- Severity disagreements — explain CVSS/business-impact reasoning transparently, don't just cite policy
- Duplicate/N-A rejections — give clear technical reasoning, not templated denial
- Disclosure timeline negotiation — balance researcher's public-disclosure interest vs. remediation SLA
- Protect signal-to-noise — retain high-quality researchers by being fair and fast, not just "policy-compliant"
- Escalate disputes to program lead/legal when policy is ambiguous, don't unilaterally overrule

**Q4. How do you communicate the same finding differently to a researcher vs. a developer?**
- Researcher-facing: validation status, severity rationale, payout/timeline, professional and concise
- Developer-facing: root cause, exploit context, PoC, concrete fix guidance — remove ambiguity that stalls fixes
- Same technical finding, different audience goals: researcher wants recognition/payout clarity; developer wants "what do I change and why"
- Tone: credibility with both — no hand-waving on technical detail either direction

**Q5. How do you turn recurring findings into program-level prevention?**
- Pattern-spot across reports: same vuln class hitting multiple services = systemic gap, not isolated bug
- Feed back into: SAST rule tuning, secure design checklists, developer training modules
- Example lens (from your IDOR notes): repeated IDOR = missing shared authZ middleware, not per-endpoint patch
- Close the loop: external discovery → internal control → measurable drop in recurrence rate

**Q6. How do you manage program scope and attack surface changes?**
- Maintain scope doc: in-scope assets, out-of-scope guidance, rules of engagement
- Evaluate new products/APIs/acquisitions before adding to scope — readiness = monitoring in place, known asset inventory, eng team briefed
- Adjust scope as program matures — narrow/broaden based on report quality and eng bandwidth
- Watch for shadow/zombie APIs entering surface unofficially

**Q7. How do you coordinate with legal/compliance on disclosure edge cases?**
- Escalate: researcher wants early public disclosure, regulatory data involved, cross-border researcher payment issues
- Understand compliance overlay (RBI/PCI-DSS/GDPR/SOX per your financial-services lens) on remediation timelines
- Don't unilaterally commit to disclosure dates — align with legal/comms first
- Document decisions for audit trail

**Q8. What program metrics would you report to leadership, and why?**
- Coverage — % of attack surface actively monitored/in-scope
- Triage velocity — time-to-first-response, time-to-validate
- Remediation cycle time — time-to-fix by severity tier
- Finding trend lines — recurring vuln classes, which teams/products generate most findings
- Frame metrics for decisions, not just reporting: e.g., rising cycle time → resourcing gap; recurring class → training gap

**Q9. How would you approach mobile and trading-infrastructure attack surfaces (vs. pure web)?**
- Mobile: static/dynamic analysis of APK/IPA, insecure storage, cert pinning bypass, API calls behind the app
- Trading infra: higher stakes for business-logic flaws (race conditions, price manipulation, order-flow tampering) — acknowledge less hands-on depth here, but conceptual grasp of stakes
- Be honest about depth gap; emphasize transferable methodology (trust boundary + data flow reasoning applies regardless of platform)

**Q10. Has your development background shaped how you give remediation guidance?**
- Understanding why devs push back — fix might break functionality, tight sprint timelines, unclear ownership
- Give guidance that's actionable: code-level pattern, not just "sanitize input"
- Anticipate friction points and address them in the write-up (e.g., migration path, phased rollout — same 7-part remediation lens you already use)
- If limited dev background: pivot to SecuLab project as evidence of hands-on fix implementation

**Q11. How would you use scripting for triage/program automation?**
- Duplicate detection — hash/fingerprint reports by endpoint + vuln class
- Scope monitoring — feed gau/waybackurls/Katana recon into attack-surface inventory (ties to your SQLite tool)
- Metrics extraction — pull platform API data (HackerOne/Bugcrowd API) into dashboards
- Low-effort, high-value automation over building anything complex — practicality matters more than cleverness here