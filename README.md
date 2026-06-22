# SpamFilter — MailEnable junk-mail marking plugin

A native SMTP plugin DLL for MailEnable that **marks** inbound junk so a MailEnable
message filter can route it to the **Junk** folder. It does **not** reject mail — it
tags only, which keeps false positives recoverable.

## What it does

At the `DATAEND` stage (the only stage where MailEnable hands the plugin the full
received message via `<messagepath>`), the plugin:

1. Sends the message to **SpamAssassin for Windows** (`spamd`) over the spamc/spamd
   protocol. SpamAssassin performs **SPF** evaluation, **DKIM** signature
   verification, and content/Bayesian scoring.
2. Computes **DMARC** itself — extracts the `From:` domain, the DKIM `d=` domain and
   the envelope sender, checks relaxed alignment against the SPF/DKIM passing
   domains, and looks up the sender's `_dmarc` TXT policy (Windows `DnsQuery`).
3. If the SA score ≥ threshold **OR** DMARC fails under `p=quarantine`/`p=reject`,
   it injects headers into the message file:
   - `X-Spam-Flag: YES`
   - `X-Spam-Status: Yes, score=… required=…`
   - `Authentication-Results: …` (spf/dkim/dmarc results, always added)
4. Always returns `1` (accept).

A MailEnable filter then moves anything with `X-Spam-Flag: YES` to Junk.

## Prerequisites

- **SpamAssassin for Windows** (JAM Software, freeware) installed and running as a
  service, with the **SPF and DKIM plugins enabled** (both are bundled/supported).
  Confirm `spamd` is listening on `127.0.0.1:783`.
- MailEnable 3.5 or later (32- and 64-bit services).
- Visual Studio with the C++ toolset (Desktop development with C++).

> DMARC needs no SpamAssassin plugin — the DLL does it. But DKIM **must** be working
> in SpamAssassin, otherwise DMARC can only pass via SPF alignment.

## Build

Build **both** architectures. The exported entry point comes from `SpamFilter.def`.

From the **x64 Native Tools Command Prompt for VS**:

```bat
cl /LD /EHsc /O2 /DNDEBUG SpamFilter.cpp /Fe:SpamFilter.dll /link /DEF:SpamFilter.def
```

From the **x86 Native Tools Command Prompt for VS** (separate prompt):

```bat
cl /LD /EHsc /O2 /DNDEBUG SpamFilter.cpp /Fe:SpamFilter.dll /link /DEF:SpamFilter.def
```

(`ws2_32.lib` and `dnsapi.lib` are pulled in automatically via `#pragma comment(lib,…)`.)

## Install

1. Copy the **32-bit** `SpamFilter.dll` + `SpamFilter.ini` to
   `C:\Program Files (x86)\Mail Enable\bin\`.
2. Copy the **64-bit** `SpamFilter.dll` + `SpamFilter.ini` to
   `C:\Program Files (x86)\Mail Enable\bin64\`.
3. Register the plugin (use `Wow6432Node` on 64-bit Windows):

   ```
   HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Mail Enable\Mail Enable\Connectors\SMTP
       Plugin DLL = SpamFilter.dll
   ```
4. Edit `SpamFilter.ini` (spamd host/port, threshold, `AuthServId` = your hostname).
5. Restart the **MailEnable SMTP** connector/service.

## MailEnable filter: route flagged mail to Junk

In the MailEnable Admin program create a message/content filter:

- **Criteria:** header `X-Spam-Flag` *contains* `YES`
- **Action:** Move to mailbox folder → `Junk Email`

(Apply it at the post-office or server scope per your setup. The exact UI path
varies by MailEnable edition/version — verify on your install.)

## Verify it's working

1. Set `Debug=1` in `SpamFilter.ini`, restart SMTP, send a test message, and check
   the `DebugLog` file for a line showing `spf=/dkim=/dmarc=/score=/tag=`.
2. Send yourself GTUBE (the SpamAssassin test string) to force a spam verdict:
   `XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X`
   The delivered message should carry `X-Spam-Flag: YES` and land in Junk.
3. Inspect a normal message's headers — you should see an `Authentication-Results`
   line with the spf/dkim/dmarc verdicts.

## Notes / known limitations (first cut)

- **Org-domain** alignment uses a simple "last two labels" rule, not a full Public
  Suffix List — imperfect for multi-part TLDs (`co.uk`, `com.au`). Swap in a PSL
  table if your senders need it.
- Only the **first** `DKIM-Signature` is considered for alignment.
- **Fails open:** if `spamd` is unreachable the message is delivered unmarked.
- Validate that header injection into `<messagepath>` is picked up by your exact
  MailEnable version before relying on it in production.
- The plugin **marks only** by design. To also hard-reject the worst offenders,
  return `0` with a `5xx` in `Response` for, e.g., `p=reject` DMARC failures.

## Configuration reference

See `SpamFilter.ini` — `SpamdHost`, `SpamdPort`, `SpamThreshold`, `EnforceDmarc`,
`SkipAuthenticated`, `AuthServId`, `TimeoutMs`, `Debug`, `DebugLog`.
