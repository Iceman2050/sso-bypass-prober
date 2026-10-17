# sso-bypass-prober

Your login page redirects to SSO. Your dashboard *looks* protected. But is `?role=admin` quietly letting strangers in — and would you ever know?

**sso-bypass-prober** probes your own login flow for the classic SSO/authentication bypasses that ship in real apps: query-param tricks, trusted-header spoofing, unprotected API paths, and HTTP method override. No dependencies, no setup — Python stdlib only.

> ⚠️ **Ethical use:** only run this tool against applications you own or have explicit permission to test. Probing systems you don't own or lack authorization for may be illegal. This tool is for testing **your own** apps.

## 30-second quickstart

```bash
git clone https://github.com/Iceman2050/sso-bypass-prober.git
cd sso-bypass-prober
python3 sso_bypass_prober.py --demo
```

`--demo` starts two **local** fixture apps (a vulnerable one and a hardened one), probes both, and shows the difference — zero setup, no network.

Probe your own staging app:

```bash
python3 sso_bypass_prober.py --target https://staging.myapp.com
```

## Example output

Real output from `python3 sso_bypass_prober.py --demo` (captured, not invented):

```
sso-bypass-prober --demo
Spinning up two LOCAL fixture apps (no network, no setup)...

== Probing http://127.0.0.1:35303  (VULNERABLE fixture) ==
  [HIGH] direct-access      http://127.0.0.1:35303/api/users
         protected path returned HTTP 200 with no session cookie
  [HIGH] query-param-bypass http://127.0.0.1:35303/dashboard?sso=false
         ?sso=false returned protected content (HTTP 200) with no session
  [HIGH] query-param-bypass http://127.0.0.1:35303/dashboard?auth=0
         ?auth=0 returned protected content (HTTP 200) with no session
  [HIGH] query-param-bypass http://127.0.0.1:35303/dashboard?logged_in=true
         ?logged_in=true returned protected content (HTTP 200) with no session
  [HIGH] query-param-bypass http://127.0.0.1:35303/dashboard?role=admin
         ?role=admin returned protected content (HTTP 200) with no session
  [HIGH] query-param-bypass http://127.0.0.1:35303/api/admin?admin=true
         ?admin=true returned protected content (HTTP 200) with no session
  [HIGH] header-injection   http://127.0.0.1:35303/dashboard
         X-Forwarded-User: admin returned protected content (HTTP 200) with no session
  [HIGH] header-injection   http://127.0.0.1:35303/dashboard
         X-Remote-User: admin returned protected content (HTTP 200) with no session
  [HIGH] header-injection   http://127.0.0.1:35303/dashboard
         X-Authenticated-User: admin returned protected content (HTTP 200) with no session
  [HIGH] header-injection   http://127.0.0.1:35303/dashboard
         X-User: admin returned protected content (HTTP 200) with no session
  [HIGH] header-injection   http://127.0.0.1:35303/api/admin
         X-Forwarded-User: admin returned protected content (HTTP 200) with no session
  [HIGH] header-injection   http://127.0.0.1:35303/api/admin
         X-Remote-User: admin returned protected content (HTTP 200) with no session
  [HIGH] header-injection   http://127.0.0.1:35303/api/admin
         X-Authenticated-User: admin returned protected content (HTTP 200) with no session
  [HIGH] header-injection   http://127.0.0.1:35303/api/admin
         X-User: admin returned protected content (HTTP 200) with no session
  [MEDIUM] method-override    http://127.0.0.1:35303/api/admin
         X-HTTP-Method-Override: GET over POST returned protected content (HTTP 200) with no session
  [MEDIUM] method-override    http://127.0.0.1:35303/dashboard
         X-HTTP-Method-Override: GET over POST returned protected content (HTTP 200) with no session
   => 16 finding(s)

== Probing http://127.0.0.1:45193  (HARDENED fixture) ==
   no findings — every bypass vector was rejected
   => 0 finding(s)

DEMO RESULT: vulnerable app exposed 16 bypass finding(s); hardened app exposed 0.
```

## What it checks

| Check | Severity | What it does |
|---|---|---|
| `direct-access` | HIGH | GETs 15 common protected API paths (`/api/users`, `/api/admin`, `/api/v1/me`, …) with no session cookie |
| `query-param-bypass` | HIGH | Tries `?sso=false`, `?auth=0`, `?logged_in=true`, `?role=admin`, `?admin=true`, … on login-adjacent paths |
| `header-injection` | HIGH | Spoofs `X-Forwarded-User`, `X-Remote-User`, `X-Authenticated-User`, `X-User` |
| `method-override` | MEDIUM | POSTs with `X-HTTP-Method-Override: GET` |

A finding = HTTP 200 with real protected content returned **without any session** (login pages and 401s are correctly ignored).

## What it does NOT do

- **Not a full pentest.** It covers four classic bypass families — not SQLi, XSS, CSRF, IDOR, or business-logic flaws.
- **No authenticated testing.** Every probe runs sessionless by design; it won't test privilege escalation *between* real users.
- **No brute force, no fuzzing.** Fixed, known-bad vectors only — it won't discover novel bypasses or hammer your server.
- **Heuristic verdicts.** A 200 with non-login content is flagged as a finding; unusual apps may need a human to confirm.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

15 tests, all green: unit tests for the probe builders and response classifier, plus integration tests that spin up the real vulnerable and hardened fixtures and assert the bypasses are found on the vulnerable app and **not** on the hardened one.

## Built by Ingenious AI

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.)

Built with Muse — try it free: invite code 2HCQH1

## License

MIT — see [LICENSE](LICENSE).
