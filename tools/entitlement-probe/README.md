# Entitlement probe

Answers one question in about ten seconds: **does this Mac let this team create a
virtual HID device?**

It builds a ~60-line app that asks IOKit for a CTAP HID device (usage page
`0xF1D0`) with nothing else in the way, signs it with the provisioning profile in
`packaging/macos/embedded.provisionprofile`, runs it, and prints a verdict. No
swpasskey code is involved, so the result cannot be blamed on the daemon.

```sh
tools/entitlement-probe/run.sh
```

It prints which profile it used, by name and UUID, so running the same profile
twice by accident is visible. To test another profile, point it at the file
directly — there is no placeholder to edit, use the newest download:

```sh
P=$(ls -t ~/Downloads/*.provisionprofile | head -1)
SWPASSKEY_PROFILE="$P" tools/entitlement-probe/run.sh
```

The signing identity is chosen from the profile's own `DeveloperCertificates`, so
a Developer ID profile is never signed with an Apple Development certificate.

## What the two answers look like

Accepted — the key will enumerate in Chrome:

```
entitlement:  1 (1 = present in the signature)
profile:      1 (1 = profile grants it)

device: CREATED

VERDICT: the kernel accepts the entitlement. A real HID key will enumerate.
```

Refused — the macOS build of swpasskey cannot produce a USB key, whatever the
signature says:

```
device: NULL

VERDICT: IOHIDUserDevice refused. Kernel line:
  kernel: IOUC IOHIDResourceDeviceUserClient failed MACF in process pid 93707, probe
```

`failed MACF` is the kernel's mandatory access control refusing the HID resource
user client. It runs before any app-level entitlement check, so a signature that
verifiably carries `com.apple.developer.hid.virtual.device` and a profile that
verifiably grants it are both necessary and — as of macOS 26.3 — not sufficient
for a team that has only self-served the capability.

## If the verdict is "refused"

`docs/entitlement-request.md` is that request, written out with this output
embedded — paste it into the form and attach the same text.

Send the probe output, the team ID and the kernel line to
<https://developer.apple.com/contact/request/system-extension/> and ask for the
**Virtual HID Device** entitlement. Apple DTS is explicit that the development
variants of the restricted entitlements are only valid in development builds and
that this one has to be applied for; a capability checkbox alone does not
populate the kernel's policy.

Until then, the working paths for the experiment are the Linux daemon
(`/dev/uhid` needs a udev rule, not an entitlement) and the socket transport used
with `tests/e2e/pyfido2_e2e.py`.

## Files

| file | role |
| --- | --- |
| `probe.mm` | the entire app: report descriptor, properties, `IOHIDUserDeviceCreateWithProperties`, one printed line |
| `run.sh` | takes the bundle ID from the profile, builds, signs, embeds the profile, runs, reads the kernel log, prints the verdict |
