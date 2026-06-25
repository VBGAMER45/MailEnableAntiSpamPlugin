# SpamFilter — MailEnable junk-mail marking plugin

A native SMTP plugin DLL for MailEnable that **marks** inbound junk so a MailEnable
message filter can route it to the **Junk** folder. It does **not** reject mail — it
tags only, which keeps false positives recoverable.

## Detection layers

Evaluated at `DATAEND` (the only stage where MailEnable hands the plugin the full
message via `<messagepath>`). Any layer firing tags the message; the **whitelist
short-circuits everything**.

1. **Whitelist** — trusted domains (subdomains included) and specific addresses are
   delivered **untouched**.
2. **TLD allow-list** — the `From:` header domain's TLD must be in `AllowedTlds`,
   else tag. Matches the final label, so `uk` covers `co.uk`.
3. **Subject keywords** — file-based list; plain lines match **whole-word**
   (case-insensitive), `re:` lines are **regex**. The file is **live-reloaded**.
4. **SpamAssassin** *(optional)* — `spamd` performs **SPF** + **DKIM** verification
   and a content/Bayesian score.
5. **DMARC** — computed in-process from the SPF/DKIM results + a `_dmarc` TXT lookup;
   tagged when it fails under `p=quarantine`/`p=reject` (only when `spamd` answered).

When a message is tagged the plugin injects:
- `X-Spam-Flag: YES`
- `X-Spam-Reason:` — which layers fired, e.g. `TLD_NOT_ALLOWED(xyz), SUBJECT_KEYWORD(lottery)`
- `X-Spam-Status:` and (if spamd answered) `X-Spam-Score:` / `Authentication-Results:`

A MailEnable filter then moves anything with `X-Spam-Flag: YES` to Junk.

> **SpamAssassin is optional.** With `UseSpamAssassin=0` (or spamd simply not
> installed yet) the whitelist/TLD/keyword layers still run — so you can deploy
> those first and add SPF/DKIM/DMARC later. The plugin **fails open**: if spamd is
> unreachable the message is delivered, and DMARC is not enforced on guessed results.

## Prerequisites

- (Optional, for SPF/DKIM/DMARC + scoring) **SpamAssassin for Windows** (JAM
  Software, freeware) running as a service with the **SPF and DKIM plugins enabled**,
  `spamd` listening on `127.0.0.1:783`.
- MailEnable 3.5 or later (32- and 64-bit services).
- Visual Studio with the C++ toolset.

## Build

Build **both** architectures. The exported entry point comes from `SpamFilter.def`.

From the **x64 Native Tools Command Prompt for VS**:

```bat
cl /LD /EHsc /O2 /DNDEBUG SpamFilter.cpp /Fe:SpamFilter.dll /link /DEF:SpamFilter.def
```

From the **x86 Native Tools Command Prompt for VS** (separate prompt): same command.

(`ws2_32.lib` and `dnsapi.lib` are linked automatically via `#pragma comment(lib,…)`.)

## Install

1. Copy the **32-bit** `SpamFilter.dll` + `SpamFilter.ini` + `SpamKeywords.txt` to
   `C:\Program Files (x86)\Mail Enable\bin\`.
2. Copy the **64-bit** `SpamFilter.dll` + `SpamFilter.ini` + `SpamKeywords.txt` to
   `C:\Program Files (x86)\Mail Enable\bin64\`.
3. Register the plugin (use `Wow6432Node` on 64-bit Windows):

   ```
   HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Mail Enable\Mail Enable\Connectors\SMTP
       Plugin DLL = SpamFilter.dll          (REG_SZ, filename only)
   ```
4. Edit `SpamFilter.ini` (see below) and set `KeywordFile` to the correct folder for
   each build (`bin\` for x86, `bin64\` for x64).
5. Restart the **MailEnable SMTP** connector/service.

## MailEnable filter: route flagged mail to Junk

In the MailEnable Admin program create a message/content filter:

- **Criteria:** header `X-Spam-Flag` *contains* `YES`
- **Action:** Move to mailbox folder → `Junk Email`

(The exact UI path varies by MailEnable edition/version — verify on your install.)

## Configuration (`SpamFilter.ini`)

| Key | Default | Meaning |
|---|---|---|
| `UseSpamAssassin` | `1` | Call spamd. `0` = local checks only. |
| `SpamdHost` / `SpamdPort` | `127.0.0.1` / `783` | Where spamd listens. |
| `SpamThreshold` | `5.0` | SA score at/above which to tag. |
| `EnforceDmarc` | `1` | Tag DMARC fails under p=quarantine/reject (needs spamd). |
| `TldFilter` | `1` | Enable the TLD allow-list. |
| `AllowedTlds` | `com uk net org us` | Allowed final-label TLDs (space/comma sep). |
| `SubjectKeywordFilter` | `1` | Enable the subject keyword filter. |
| `KeywordFile` | *(path)* | Path to `SpamKeywords.txt`. |
| `KeywordReloadSeconds` | `5` | Min seconds between keyword-file reload checks. |
| `WhitelistDomains` | *(empty)* | Trusted domains, subdomains included. |
| `WhitelistSenders` | *(empty)* | Trusted exact addresses. |
| `AuthServId` | `mail.local` | authserv-id in Authentication-Results (use your hostname). |
| `TimeoutMs` | `10000` | spamd socket timeout. |
| `Debug` / `DebugLog` | `0` / *(path)* | One log line per scanned message. |

### Keyword file syntax (`SpamKeywords.txt`)

```
# comment
lottery                 # whole-word, case-insensitive
wire transfer           # phrases work
re:v[i1]@?gra           # regex (ECMAScript, case-insensitive)
re:\bact now\b
```

Edits take effect within `KeywordReloadSeconds` — **no restart needed** for keyword
changes (other INI settings still need an SMTP restart).

## Verify it's working

1. Set `Debug=1`, restart SMTP, send test mail, and read the `DebugLog` line:
   `from=[…] dom=[…] tld=[…] tag=0/1 reasons=[…] sa-ok/sa-off/sa-unreachable`.
2. Send from a disallowed TLD (e.g. a `.xyz` address) → should be tagged
   `TLD_NOT_ALLOWED(xyz)` and land in Junk.
3. Put a word from `SpamKeywords.txt` in a subject → tagged `SUBJECT_KEYWORD(...)`.
4. Add the sender's domain to `WhitelistDomains` → next message delivers untouched.
5. (If spamd is up) GTUBE forces a spam verdict:
   `XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X`

## Notes / known limitations

- The **TLD allow-list is aggressive** — your 5 TLDs also block `.edu .gov .ca .de
  .au .io .co .info …`. Widen `AllowedTlds`, or lean on `WhitelistDomains` for the
  exceptions you trust.
- **Whole-word** keyword matching is ASCII-boundary based; for obfuscated text use a
  `re:` regex. Substring-style catches can be done with regex too (`re:cialis`).
- **Org-domain** alignment uses a "last two labels" rule, not a full Public Suffix
  List — imperfect for multi-part TLDs (`co.uk`). Swap in a PSL table later if needed.
- Only the **first** `DKIM-Signature` is considered for alignment.
- The plugin **marks only**. To hard-reject the worst offenders, return `0` with a
  `5xx` in `Response` (e.g. for `p=reject` DMARC failures).
- Validate that header injection into `<messagepath>` is honored by your exact
  MailEnable version before relying on it in production.
