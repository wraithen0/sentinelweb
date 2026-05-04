# Ethics & Acceptable Use

SentinelWeb is a **defensive** security framework intended for **authorized**
testing only — bug bounty programs, internal security assessments, CTFs you own,
and other engagements where you have **explicit, written permission** to test
the target.

## Hard rules

1. **No testing without authorization.** Every scan requires a `scope.yaml`
   declaring in-scope hosts. The framework will refuse to run without it and
   will refuse to send traffic to any host not listed.
2. **No destructive payloads.** Detection modules emit signal-only probes.
   Nothing in this framework is designed to exfiltrate data, modify state,
   pivot into infrastructure, or persist on a target.
3. **Respect rate limits.** Configure conservative rates in `scope.yaml`.
   Default is intentionally slow.
4. **Audit trail.** Every run writes a tamper-evident audit log
   (`audit.jsonl`) of which targets were probed, with what, and when. Keep
   these logs — bug bounty programs and internal compliance teams may ask
   for them.
5. **Disclose responsibly.** If you find a vulnerability, follow the
   program's disclosure policy. Do not publish details before the issue is
   fixed and disclosure is coordinated.

## What SentinelWeb is NOT

- Not an exploit framework (no Metasploit-style modules).
- Not a credential stuffer / password cracker.
- Not a C2 / post-exploitation tool.
- Not a mass scanner that sprays the internet.

If you need any of the above, this is not the right tool — and depending on
your context, may not be legal. Consult your engagement's rules of engagement
and legal counsel.

## Reporting abuse

If you observe SentinelWeb being used against systems without authorization,
please open an issue at https://github.com/wraithen0/sentinelweb/issues with
"abuse" in the title.
