# Alert Investigation Template
**Alert ID:** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; **Date/Time:** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; **Analyst:**

---

## 1. Initial Snapshot

| Field | Value |
|---|---|
| Alert Name | |
| Severity | Critical / High / Medium / Low |
| Source IP | |
| Destination IP | |
| Hostname | |
| User | |
| What triggered it | |

**First impression:** *(Phishing / Malware / Brute Force / False Positive / Other)*

---

## 2. The Big 5 Questions

- [ ] Is this malicious? `Y / N / Unknown`
- [ ] Was it successful? `Y / N / Partial`
- [ ] Is it still happening? `Y / N`
- [ ] Are other systems affected? `Y / N`
- [ ] Do we need to contain RIGHT NOW? `Y / N`

> ⚡ If YES to containment → jump to Section 6 first, then come back.

---

## 3. Investigation Notes

| Time | What I Checked | What I Found |
|---|---|---|
| | | |
| | | |
| | | |
| | | |

---

## 4. Threat Intel

| Tool | Result | Notes |
|---|---|---|
| **VirusTotal** | `/` engines flagging | |
| **AbuseIPDB** | `%` confidence score | |
| **Talos** | Reputation: | |
| **WHOIS** | Country: &nbsp;&nbsp; Org: | |
| **URLScan / URLhaus** | Listed: Y / N | |

**OSINT Verdict:** `Clean / Suspicious / Malicious`

---

## 5. IOCs Found

```
IPs:       
Domains:   
Hashes:    
Files:     
Processes: 
Emails:    
```

---

## 6. Containment Actions

| Action | Target | Time Done |
|---|---|---|
| [ ] Isolate endpoint | | |
| [ ] Block IP/domain | | |
| [ ] Disable user account | | |
| [ ] Quarantine file | | |
| [ ] Other: | | |

---

## 7. Verdict

**Decision:** `True Positive / False Positive / Benign TP`

**Confidence:** `High / Medium / Low`

**Attack successful?** `Yes / No / Partial`

**MITRE Techniques:** *(e.g. T1566 - Phishing, T1059 - Command Execution)*

---

## 8. Closing Summary

**What happened:** *(2-3 sentences max)*

**Actions taken:**

**Recommendations:**

**Escalate?** `Yes → to: _______ / No`