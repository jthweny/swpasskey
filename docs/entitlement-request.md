# Entitlement request: Virtual HID Device

Everything below is ready to paste into
<https://developer.apple.com/contact/request/system-extension/> (choose the
entitlement request, "Virtual HID Device"). The two output blocks are verbatim
from `tools/entitlement-probe/run.sh` on the affected Mac (macOS 26.3.1,
Apple silicon); re-run it before submitting if the OS or the profiles changed.

Attach: the two blocks below, and optionally `tools/entitlement-probe/probe.mm`
(the entire reproduction is 60 lines).

---

## Request text

**Team ID:** J95YN52A9A (Joshua Thweny)
**App ID / bundle identifier:** `com.jthweny.swpasskey.daemon`
**Entitlement requested:** `com.apple.developer.hid.virtual.device`

I'm building a FIDO2 authenticator emulator for compatibility testing of
relying-party attestation handling: it presents itself as a USB HID FIDO device
(usage page `0xF1D0`) so that WebAuthn flows, attestation formats and
authenticator metadata can be exercised without dedicated hardware.

I enabled **HID Virtual Device** on the App ID above and created a macOS App
Development provisioning profile that contains
`com.apple.developer.hid.virtual.device`. Signing verifies: the entitlement is in
the signature, the bundle identifier matches the profile's
`com.apple.application-identifier`, the profile is embedded in the app bundle,
and the app is signed with the certificate the profile lists.

`IOHIDUserDeviceCreate` nevertheless returns null with `IOServiceOpen
0xe00002e2`, and the kernel logs a MACF refusal:

```
IOUC IOHIDResourceDeviceUserClient failed MACF in process pid …, probe
```

To rule out my own code I reduced the reproduction to a 60-line command-line app
that builds a CTAP HID report descriptor and calls
`IOHIDUserDeviceCreateWithProperties` once. It fails identically. Adding
`com.apple.security.get-task-allow` changes nothing.

The Developer ID profile for the same App ID is issued **without**
`com.apple.developer.hid.virtual.device` (see the second block), so distribution
signing cannot carry it either. That suggests the team has not been granted the
entitlement and that ticking the capability in the portal is not sufficient.

Could you grant the Virtual HID Device entitlement to team J95YN52A9A, or advise
what else is required? I'm happy to provide the reproduction app, a sysdiagnose,
or to test a signed build against the entitlement.

---

## Probe output 1: development profile that grants the entitlement

```
profile path: /Users/adminuser/VirtualYubi/swpasskey/packaging/macos/embedded.provisionprofile
profile name: swpasskey daemon dev
profile uuid: 13fa908a-6996-451d-b4fa-20d2ebbe7d38
created:      2026-11-10T04:46:10Z
expires:      2027-11-10T04:46:10Z
kind:         development (has a registered-device list)
bundle id:    com.jthweny.swpasskey.daemon
team:         J95YN52A9A
identity:     Apple Development: Joshua Thweny (5G4RMX5PC7)
entitlement:  1 (1 = present in the signature)
grant:        1 (1 = profile grants it)

pid: 95189
device: NULL

VERDICT: IOHIDUserDevice refused. Kernel line:
  2026-11-10 05:04:29.190710+0000 0x2a3d5a   Default     0x0                  0      0    kernel: IOUC IOHIDResourceDeviceUserClient failed MACF in process pid 95189, probe

  "IOUC IOHIDResourceDeviceUserClient failed MACF" is the kernel's mandatory
  access control refusing the HID resource user client. It is not caused by this
  probe, by swpasskeyd, or by anything in the app's own code: the check runs
  before the app's entitlement-aware code path is reached.

  Attach this output (bundle id, team, and that kernel line) to an entitlement
  request at developer.apple.com/contact/request/system-extension/ and ask for
  the Virtual HID Device entitlement for the team.
```

## Probe output 2: Developer ID profile for the same App ID

```
profile path: /Users/adminuser/Downloads/swpasskey_daemon_devid.provisionprofile
profile name: swpasskey daemon devid
profile uuid: d2ac67e0-71cc-4753-bc70-9c2e51178c11
created:      2026-11-10T05:02:07Z
expires:      2044-11-05T05:02:07Z
kind:         distribution-style (no device list)
bundle id:    com.jthweny.swpasskey.daemon
team:         J95YN52A9A
identity:     Developer ID Application: Joshua Thweny (J95YN52A9A)
entitlement:  1 (1 = present in the signature)
grant:        0 (1 = profile grants it)

(truncated: the run stops here because the profile contains no
 com.apple.developer.hid.virtual.device entitlement)
```
