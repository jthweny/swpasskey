# What is left to test

Everything below is a *measurement*, not a bypass attempt. Rows 1-29 plus the four
client-side probes are in `docs/RESEARCH-BRIEF.md`; `docs/CONCLUSION.md` states where
the boundary sits.

| # | item | state |
| --- | --- | --- |
| 1 | **Delayed re-classification** — users report the hardware verdict flipping days after enrolment; every verdict recorded here was read within minutes | **instrumented**: the extension samples the credential list every 10 minutes on an `auth.openai.com` page and appends to `/tmp/flag-timeline.jsonl`. Needs one extension reload. |
| 2 | **`fmt: "fido-u2f"`** — the statement is signed by the *credential* key over `0x00‖rpIdHash‖cdh‖credId‖pubKey`, so a software authenticator can make it genuinely valid under an unregistered certificate | **built** (`tools/browser-bridge/alt_formats.py`), python-fido2 returns `AttestationType.BASIC`. Live enrolment blocked on an account session. |
| 3 | **`fmt: "android-key"`** — KeyDescription extension with `attestationChallenge = cdh`; chain is expected to reach a Google root, which ours does not | **built**; python-fido2 ships no verifier for this format, so it can only be tested live. |
| 4 | **Assertion, then re-read the flags** — is the hardware classification computed at registration only, or re-evaluated when the credential is used? | needs an explicit decision: this signs in to the live account with the virtual credential |
| 5 | **`transports: ["usb","nfc"]`** — all 29 rows sent `["usb"]`; the site serialises `transports` into the registration POST | **ready** via `window.__SWPK_TRANSPORTS`; needs one extension reload |

Reloading the extension once covers 1 and 5; a signed-in tab covers 2 and 3. None of
these require new hardware or vendor material, and none changes a verification result
on a third party's behalf — they only observe how the account's own credential list
behaves.
