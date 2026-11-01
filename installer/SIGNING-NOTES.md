# Signing Notes - fixing "UNKNOWN PUBLISHER" for SecuDrive

## The problem

Windows shows **Unknown Publisher** on the UAC prompt and in Explorer's
**Details** tab even when `version_info.txt` is populated.  That metadata
(company, product, description, copyright) proves *who we claim to be*, but
it is **not cryptographically verified**.  Only an **Authenticode code-signing
certificate** removes the "Unknown Publisher" warning and the yellow SHA-1 /
"unverified publisher" banner.

> Summary: version metadata = what you *say*.  A code-signing cert = what a
> trusted CA *vouches for*.  You need both for Windows (and Windows Security
> Center, bug #12) to treat the binary as a legitimate product.

## Step 1 - version metadata (done via build)

`SecuDrive.spec` already passes `version=assets/version_info.txt`, which now
carries:

- CompanyName  = SecuDrive Software
- ProductName  = SecuDrive
- FileDescription = SecuDrive - USB Security & Data Recovery
- LegalCopyright = Copyright (c) 2026 SecuDrive Software

Rebuild with `python build.py` and check Explorer > Properties > Details.

## Step 2 - get an Authenticode certificate

Options (pick one):

1. **OV (Organization Validation) certificate** - e.g. DigiCert, Sectigo,
   GlobalSign.  Costs ~$100-300/yr, requires your registered company
   documents.  The minimum that clears the "Unknown Publisher" warning.
2. **EV (Extended Validation)** - stricter vetting, gives immediate Windows
   SmartScreen reputation.  More expensive; recommended only for public
   distribution.
3. **Self-signed test certificate** - `New-SelfSignedCertificate` for local
   testing only.  Windows will still warn; it is *not* a fix, just a way to
   test the signing pipeline.

You receive a `.pfx` (or `.p12`) file + password.  Keep it in a vault; never
commit it to the repository (add it to `.gitignore`).

## Step 3 - sign the exe with signtool (Windows SDK)

```powershell
# Timestamped SHA-256 signing - the modern Baseline baseline
signtool sign /f SecuDriveCert.pfx /p <PFX-PASSWORD> ^
    /fd sha256 /tr http://timestamp.digicert.com /td sha256 ^
    /v dist\SecuDrive.exe

# Verify
signtool verify /pa /v dist\SecuDrive.exe
```

Or sign through Inno Setup so the **installer** is signed too (recommended -
then the UAC prompt for Setup.exe and every extracted file is trusted):

1. Uncomment the `SignTool=` line near the top of `installer\SecuDrive.iss`.
2. Build with: `ISCC.exe installer\SecuDrive.iss /Ssigntool="...path...\signtool.exe sign /f cert.pfx /p pass /fd sha256 /tr http://timestamp.digicert.com /td sha256 $f"`
3. Note: the `$f` placeholder is how Inno passes each produced file
   (uninstaller + installer) to signtool.

## Step 4 - SmartScreen reputation

A signed OV binary still may show a *one-time "Windows protected your PC"*
SmartScreen prompt for brand-new products.  That fades as download reputation
grows; EV certificates skip it immediately.  Nothing in code fixes this - it
is a trust-reputation mechanic.

## Why this matters for Security Center registration (wsc_register.py)

Windows Security Center (bug #12) lists transient providers but the
**Security Health service filters products it cannot verify** - an unsigned
AV binary is commonly hidden or flagged.  The registry registration in
`secudrive/wsc_register.py` will only "stick" visibly once SecuDrive.exe is
properly signed.  Plan for the certificate before relying on WSC listing.

## Checklist before public release

- [ ] `python build.py` rebuilt `dist\SecuDrive.exe`
- [ ] Explorer Details show Company/Product/Copyright
- [ ] `signtool verify /pa` passes on `dist\SecuDrive.exe`
- [ ] Setup.exe signed (Inno `SignTool=`), install on clean Win10 + Win11
- [ ] No "Unknown Publisher" on the UAC prompt for installer or app
- [ ] Optional: Windows Security Center lists SecuDrive after install