# Security Assessment of iSpy Open-Source Video Surveillance Software

A source-level security assessment of [iSpy](https://github.com/ispysoftware/iSpy), an open-source Windows video surveillance application (~400 C# files, .NET Framework 4.8). The assessment identified five vulnerabilities in the authentication subsystem, mapped each to a CWE category, and delivered working patches for two of them.

**Course:** CSCE 5565 — Secure Software Systems
**Institution:** University of North Texas
**Semester:** Spring 2026
**Team:** Group project — Simon Richards, Sreeja Badri, Aryan Kumar, Dinesh Melimi


---

## What this assessment covered

iSpy is a long-running open-source video surveillance application that records and streams from webcams and IP cameras and exposes an embedded HTTP server for remote access. It is frequently deployed by non-specialist users in homes and small businesses, so weaknesses in its authentication subsystem translate directly into privacy risk for end users. No published audit of iSpy's auth subsystem existed when the assessment began.

The assessment was scoped to the authentication subsystem specifically:

- The local credential store and the desktop lock screen (`CheckPassword.cs`)
- The cryptography utility used to persist credentials (`EncDec.cs`)
- The embedded HTTP server's authentication mechanism (`Server/LocalServer.cs`)
- Brute-force protections (or, as it turned out, the absence of them)

The full audit, threat model, finding catalogue, and patches are in [`CSCE_5565_Final_Project_Report.pdf`](CSCE_5565_Final_Project_Report.pdf).

---

## Findings

Five issues were identified through static source review supplemented by dynamic interaction with a locally built instance.

| ID | Vulnerability | CWE | Severity | Patched |
|----|---|---|---|---|
| F-01 | Reversible AES used for password storage | [CWE-257](https://cwe.mitre.org/data/definitions/257.html) | Critical | Yes |
| F-02 | Hardcoded salt (`"Salt"`) and hardcoded GUID master key | [CWE-760](https://cwe.mitre.org/data/definitions/760.html), [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Critical | Partial |
| F-03 | Auth token transmitted in URL query strings | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | Medium | No |
| F-04 | No rate limiting on authentication failures | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | High | Yes |
| F-05 | MD5 in outbound HTTP Digest authentication | — | Informational | No |

### The most consequential finding: F-01

The login path stored every password as the output of `EncDec.EncryptData` and decrypted it on every login attempt to compare by string equality:

```csharp
if (txtPassword.Text == EncDec.DecryptData(g.password, MainForm.Conf.EncryptCode))
{
    // login successful
}
```

This means the password was *recoverable*, not hashed. Anyone with read access to the iSpy config file (plus the encryption key, which sits in the same file) could recover every plaintext password instantly — no cracking step required. This is materially worse than even a fast, unsalted-MD5 hash, because there is no work factor at all between the attacker and the plaintext.

### Why the salt didn't help

`EncDec.cs` derives its AES key with the literal four-byte salt `"Salt"`:

```csharp
var pdb = new PasswordDeriveBytes(password, Encoding.UTF8.GetBytes("Salt"));
```

That value is identical across every iSpy installation in the world. A salt that ships in the binary is not a salt — it provides none of the protection a salt is meant to provide.

---

## Fixes delivered

Two of the five findings were addressed with working patches against the actual iSpy source.

### Fix 1 — PBKDF2 password hashing ([Fix1_PasswordHashing.txt](fixes/Fix1_PasswordHashing.txt))

Replaced the reversible AES round-trip with one-way PBKDF2-HMAC-SHA256 hashing:

- 128-bit per-record CSPRNG-generated salt (replacing the global `"Salt"` literal)
- 100,000 iterations (OWASP 2023 minimum for PBKDF2-SHA256)
- Stored format: `PBKDF2$<iter>$<base64Salt>$<base64Hash>`
- Constant-time verification to prevent timing attacks
- **Transparent legacy migration** — old AES-encrypted records are detected on next login, verified against the old scheme one final time, and silently rehashed under PBKDF2. No forced password reset for existing installations.

Per-call verification cost measured at ~101 ms on a commodity Windows host, which caps an online attacker's guess rate at roughly 9 attempts per second per core — a reduction of several orders of magnitude relative to the original instant-equality check, before considering the F-04 throttle.

A Python reference implementation ([test_password_hasher.py](fixes/test_password_hasher.py)) was written to validate the storage format and the cryptographic behavior of the new hasher independently of the C# code path.

### Fix 2 — IP-based login throttle ([Fix2_LoginThrottle.txt](fixes/Fix2_LoginThrottle.txt))

A new `Server/LoginThrottle.cs` class, backed by a `ConcurrentDictionary` keyed on remote IP. Behavior:

- After 5 failed `CheckAuth` comparisons within a 10-minute sliding window, the IP is locked out for 15 minutes
- Locked-out requests receive an HTTP 429 response with `errorType: "ratelimit"` so the front-end can distinguish lockout from a normal auth failure
- Successful authentication clears the counter
- Thread-safe under concurrent access

**Why IP-keyed and not user-keyed:** iSpy's embedded server uses a single shared GUID for authentication (`MainForm.Identifier`), not a per-user credential sent over the wire. Per-IP is the only meaningful scope for throttling in that design.

The integration changes touch `LocalServer.cs` in three places: the `CheckAuth` signature now takes a `remoteIp`, the caller extracts that IP from the request endpoint, and the 429 response path returns before the normal auth-failure handler.

---

## What was left unfixed and why

**F-02 (hardcoded `WSPassword` GUID)** is partially mitigated by Fix 1 for the user-account path, because the broken `EncDec` flow is no longer used there. The hardcoded GUID protecting `WSPassword` itself remains. A proper fix would migrate that field to Windows DPAPI (`ProtectedData.Protect`), scoping the encryption key to the current Windows user account and removing the literal entirely. That change touches the upstream web-service handshake and was out of scope.

**F-03 (auth token in URL query string)** requires migrating the embed URLs in `CameraWindow.cs` and `VolumeLevel.cs` to either the `Authorization` header or a short-lived signed-URL scheme. Either is a non-trivial protocol change and was out of scope.

**F-05 (MD5 in outbound HTTP Digest)** is a property of the HTTP Digest specification rather than a defect in iSpy. Recorded for completeness only.

---

## Lessons drawn from the assessment

A few takeaways are worth surfacing for anyone reading this:

**Encryption is not authentication.** The most consequential defect was the use of a reversible cipher to store something that should never have been recoverable. Once a password can be decrypted, every control around it (file permissions, the per-installation key, the OS user model) is reduced to "trust the file system." When that assumption fails, the credential is gone. The lesson is to use a one-way password-hashing primitive unconditionally — if a system needs to recover the original password, the design itself is wrong.

**A salt that ships in the binary is not a salt.** The literal `"Salt"` in `EncDec.cs` is a useful illustration of how cryptographic guidance fails when implemented mechanically. The author appears to have known a salt was required and produced something that satisfied the API — but the value is global, four bytes, and visible to every attacker. The same lesson applies to the hardcoded GUID guarding `WSPassword`: secrecy of source and secrecy of keys are different things.

**Throttling needs to be the first thing the auth function does, not the last.** Any custom authentication path needs a corresponding throttle, and it needs to gate the work rather than follow it. The complete absence of failed-attempt accounting in iSpy is a direct consequence of writing the HTTP listener by hand instead of building on a framework that provides it for free.

**Threat modeling pays for itself.** Drafting the STRIDE table before reading any code directed attention to the information-disclosure and elevation-of-privilege rows — which is where all four of the meaningful findings landed. Without that step, the assessment would likely have spent its time on the larger but less-impactful camera and recording paths.

---

## Repository contents

```
.
├── README.md                              # This file
├── CSCE_5565_Final_Project_Report.pdf     # Full assessment report
├── LICENSE
├── .gitignore
└── fixes/
    ├── Fix1_PasswordHashing.txt           # PasswordHasher.cs + diffs against iSpy source
    ├── Fix2_LoginThrottle.txt             # LoginThrottle.cs + diffs against iSpy source
    └── test_password_hasher.py            # Python reference implementation for validation
```

The `.txt` files contain new C# source files followed by unified diffs against the relevant iSpy files (`CheckPassword.cs`, `PermissionsForm.cs`, `MainForm_Configuration.cs`, `LocalServer.cs`). They are not standalone — they are the implementation artifacts referenced by Section V of the report.

---

## Responsible disclosure

The findings were discovered as a class assignment in 2026. The vulnerabilities exist in publicly released versions of iSpy and have not been formally reported upstream by the assessment team. Anyone reproducing this work for the iSpy maintainers' benefit is encouraged to file the issues through the project's GitHub.

---

## About me

Graduate student in Cybersecurity at the University of North Texas, focusing on secure software systems.

- LinkedIn: [Simon Richards](https://www.linkedin.com/in/simon-richards-0a65b216a/)
- Email: symon.510@gmail.com
