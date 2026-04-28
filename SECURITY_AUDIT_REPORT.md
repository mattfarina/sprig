# Sprig Security Audit Report

**Repository:** `github.com/Masterminds/sprig/v3`
**Branch audited:** `claude/security-audit-report-WBvZE`
**Audit date:** 2026-04-28
**Go module version:** `go 1.23.0` (toolchain `go1.24.4`)
**Scope:** All Go source files in the module root (`crypto.go`, `defaults.go`,
`dict.go`, `list.go`, `numeric.go`, `regex.go`, `strings.go`, `url.go`,
`network.go`, `date.go`, `reflect.go`, `semver.go`, `functions.go`,
`doc.go`) and the declared dependency tree in `go.mod` / `go.sum`.

## 1. Executive summary

Sprig is a function library that ships >100 helpers for Go's
`text/template` and `html/template` engines. Although the package is
"only" a template helper library, several of its functions (AES
encryption, password derivation, certificate generation, htpasswd, RNG,
URL parsing, regex evaluation) are commonly invoked on
attacker-influenced inputs in tools that embed Sprig (Helm, Argo,
Kustomize-style renderers, custom config generators, etc.). Findings are
therefore evaluated against that downstream usage model.

Overall posture: **dependencies are current and free of known CVEs at
the versions pinned in `go.sum`**, but the package contains a number of
**long-standing cryptographic mis-designs** and **panic-prone code
paths** that an attacker who controls template inputs can use to either
weaken security guarantees or crash the renderer.

| Severity        | Count |
|-----------------|-------|
| Critical        | 0     |
| High            | 3     |
| Medium          | 7     |
| Low / Info      | 9     |

The High findings are concentrated in `crypto.go`. The Medium findings
are dominated by `panic`s on attacker-controlled input that can be
weaponised as a denial-of-service against any process that renders
untrusted templates.

## 2. High severity findings

### H-1. `encryptAES` / `decryptAES`: unauthenticated CBC + raw-password key

**Files:** `crypto.go:624-680`
**Functions:** `encryptAES`, `decryptAES`

```go
key := make([]byte, 32)
copy(key, []byte(password))
block, err := aes.NewCipher(key)
...
mode := cipher.NewCBCEncrypter(block, iv)
mode.CryptBlocks(ciphertext[aes.BlockSize:], content)
```

Three independent problems combine here:

1. **No KDF.** The user-supplied `password` is copied byte-for-byte into
   a 32-byte buffer. Passwords shorter than 32 bytes are zero-padded;
   passwords longer than 32 bytes are silently truncated. The effective
   key entropy is bounded by the first 32 bytes of the password and is
   far below 256 bits in any realistic use. There is no salt, no
   iteration count, and no use of PBKDF2/Argon2/scrypt (despite scrypt
   already being imported by this very file).
2. **No authentication.** AES-CBC with a random IV provides
   confidentiality but no integrity. An attacker with access to a
   "decryption oracle" (any service that decrypts and reacts
   differently to padding errors vs. plaintext errors) can mount a
   classic Vaudenay padding-oracle attack and recover plaintext one
   byte at a time. It is also trivially malleable: flipping bits in
   block N flips the same bits in block N+1's plaintext.
3. **Padding is checked unsafely on decryption.** `decryptAES` ends
   with:
   ```go
   return string(decrypted[:len(decrypted)-int(decrypted[len(decrypted)-1])]), nil
   ```
   The last byte is treated as the PKCS#7 pad length and used as a
   slice bound *with no validation*. If the padding byte is larger than
   `len(decrypted)`, this panics with `slice bounds out of range`.

**Recommendation.** Replace with AES-GCM (`crypto/cipher.NewGCM`) keyed
via `golang.org/x/crypto/scrypt` or `argon2id` over the password and a
random salt; prepend the salt and nonce to the ciphertext. As a
transitional measure, document that `encryptAES`/`decryptAES` are
**not** authenticated and **must not** be used to encrypt
attacker-influenced data.

### H-2. `htpasswd` SHA mode produces unsalted SHA-1 hashes

**File:** `crypto.go:69-95`

```go
func hashSha(password string) string {
    s := sha1.New()
    s.Write([]byte(password))
    passwordSum := []byte(s.Sum(nil))
    return base64.StdEncoding.EncodeToString(passwordSum)
}
```

The `htpasswd` template function exposes Apache's legacy `{SHA}` scheme,
which is unsalted SHA-1. SHA-1 is collision-broken (SHAttered, 2017)
and unsalted hashes of human-chosen passwords are trivially defeated
with rainbow tables. Apache itself flags this scheme as "for
compatibility only".

**Recommendation.** Either remove the `HashSHA` branch entirely, or at
minimum return an explicit error/string warning when `HashSHA` is
selected and update the docs to prohibit it for new deployments. The
default branch (bcrypt) should remain.

### H-3. `genPrivateKey "dsa"` produces deprecated DSA keys

**File:** `crypto.go:174-202`

```go
case "dsa":
    key := new(dsa.PrivateKey)
    if err = dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L2048N256); err != nil {
        return fmt.Sprintf("failed to generate dsa params: %s", err)
    }
    err = dsa.GenerateKey(key, rand.Reader)
```

DSA was removed from FIPS 186-5 (2023) and is deprecated by NIST.
Go itself has soft-deprecated `crypto/dsa` (the package is in
maintenance mode and no longer receives improvements). Keys generated
here will be rejected by modern TLS stacks, OpenSSH ≥ 9, and most CAs.

**Recommendation.** Drop the `dsa` branch, or print a clear deprecation
notice and steer callers toward `ecdsa` / `ed25519`.

## 3. Medium severity findings

These are largely **DoS via panic** on attacker-controlled input.
Because Go templates propagate panics out of the template engine unless
`html/template`'s `Execute` is wrapped in `recover`, a single crafted
value will tear down the calling goroutine.

### M-1. `decryptAES` panics on malformed ciphertext

**File:** `crypto.go:655-680`

`decryptAES` performs no length checks before slicing `crypt[:aes.BlockSize]`
or before calling `mode.CryptBlocks(decrypted, crypt)`. A ciphertext
shorter than 16 bytes, or one whose length is not a multiple of the
block size, will panic. The trailing pad-length read described in H-1
is also a panic source.

**Recommendation.** Validate `len(crypt) >= 2*aes.BlockSize`, that
`len(crypt) % aes.BlockSize == 0`, and that the pad byte is in
`[1, aes.BlockSize]` and matches the trailing bytes (constant-time).

### M-2. `urlParse` panics on parse errors

**File:** `url.go:22-42`

```go
parsedURL, err := url.Parse(v)
if err != nil {
    panic(fmt.Sprintf("unable to parse url: %s", err))
}
```

Any caller that pipes user input into `urlParse` can be crashed with a
malformed URL. `url.Parse` is permissive, so reaching this branch is
hard but not impossible (e.g. `http://[::1`).

**Recommendation.** Return an empty map and an error (or, to preserve
template ergonomics, an empty map silently). Mirror the existing
`must*` / non-`must*` split used elsewhere in the package.

### M-3. `urlJoin` panics via `dictGetOrEmpty`

**File:** `url.go:9-19, 45-66`

`dictGetOrEmpty` panics when a value in the dict is anything other than
a string. The same function also panics on userinfo parse errors. A
template author who passes a dict with, say, an integer port leaks a
panic to the runtime.

**Recommendation.** Coerce non-string values via `strval` (already
defined in `strings.go`) and return an empty string on failure rather
than panicking.

### M-4. `dig` panics on type assertions and arity

**File:** `dict.go:150-174`

```go
dict := ps[len(ps)-1].(map[string]interface{})
...
ks[i] = ps[i].(string)
...
return digFromDict(step.(map[string]interface{}), d, ns)
```

Three uncovered failure modes:

1. `len(ps) < 3` panics explicitly via `panic("dig needs at least three arguments")`.
2. Final argument not a `map[string]interface{}` → unrecovered type-assertion panic.
3. Nested key encountered whose value is not a map → unrecovered panic in `digFromDict`.

**Recommendation.** Replace the bare type assertions with the
two-value comma-ok form and surface a friendly error string the way
the rest of the package does.

### M-5. `chunk` divides by zero on `size <= 0`

**File:** `list.go:85-118`

```go
cs := int(math.Floor(float64(l-1)/float64(size)) + 1)
```

When `size == 0`, `float64(l-1)/0` produces `+Inf` and the subsequent
`int(...)` conversion result is implementation-defined. When `size < 0`,
the `make([][]interface{}, cs)` call can panic on a negative or
absurdly large length. Both are reachable if `chunk` is called with a
template-supplied size.

**Recommendation.** Reject `size <= 0` early with an explicit error.

### M-6. `getHostByName` panics on lookup failure

**File:** `network.go:8-12`

```go
addrs, _ := net.LookupHost(name)
return addrs[rand.Intn(len(addrs))]
```

The `_` discards `err`. If `LookupHost` returns no results,
`rand.Intn(0)` panics. The function also relies on `math/rand` (not
`crypto/rand`) without seeding, so until Go 1.20 it returned the same
sequence each run; on Go 1.20+ the global `rand` is auto-seeded so this
is no longer a determinism issue, but the panic remains. Selecting an
IP from a DNS result set with `math/rand` is also not cryptographically
useful.

**Recommendation.** Check the error, return `""` (or all addresses
joined) on failure, and document the function as **non-hermetic** (it
already is, in `nonhermeticFunctions`).

### M-7. `regexFind*`, `regexReplace*`, `regexSplit` panic on invalid regex

**File:** `regex.go:16-79`

The non-`must*` variants use `regexp.MustCompile`, which panics on
malformed expressions. Templates that pipe user-controlled regex
patterns can crash the renderer.

Note: Go's `regexp` is RE2, so ReDoS via catastrophic backtracking is
**not** a concern here — this finding is strictly about the panic.

**Recommendation.** Either (a) document that the non-`must` variants
are unsafe for untrusted regex input, or (b) change them to fall back
to `regexp.Compile` and return an empty result on compile error.

## 4. Low / informational findings

### L-1. `bcrypt` uses `DefaultCost` (= 10)

**File:** `crypto.go:60-67`

`bcrypt.DefaultCost` is 10. Modern guidance (OWASP 2023) recommends a
work factor of at least 12 for bcrypt. The function takes no parameter
to override the cost.

**Recommendation.** Add an optional cost parameter, or hard-code `12`.

### L-2. `derivePassword` uses scrypt with a deterministic salt

**File:** `crypto.go:137-172`

The salt is derived from the master-password seed and the username, so
two users with identical names share the same salt. This is intentional
in the upstream "Master Password" algorithm (the function is
deterministic by design), but consumers should be made aware that this
**is not a generic password hashing function** and must not be used
for verification storage.

**Recommendation.** Add a doc comment explicitly contrasting this with
`bcrypt` and pointing out that the function is reproducible by anyone
who knows the master password, user, site and counter.

### L-3. CAs and self-signed certs use 2048-bit RSA

**File:** `crypto.go:344, 392, 439`

While 2048-bit RSA is still considered acceptable through 2030 (NIST
SP 800-57), the standalone `genPrivateKey "rsa"` path generates 4096
bits. The cert-generating helpers should match.

**Recommendation.** Bump RSA key size in `generateCertificateAuthority`,
`generateSelfSignedCertificate`, and `generateSignedCertificate` to
3072 or 4096, or expose the key size as a parameter.

### L-4. `randInt` uses non-cryptographic `math/rand`

**File:** `functions.go:210`

```go
"randInt": func(min, max int) int { return rand.Intn(max-min) + min },
```

This is appropriate for layout/jitter use cases but is named in a way
that may be mistaken for a security primitive. Also panics if
`max <= min` (`rand.Intn(0)` or negative argument).

**Recommendation.** Document that `randInt` is non-cryptographic
(adjacent to `randAlpha*` which already use `crypto/rand` via
`goutils`). Add an early return for `max <= min`.

### L-5. `base64decode` / `base32decode` return error text in-band

**File:** `strings.go:18-36`

On decode failure these return `err.Error()` cast to a string, so the
caller receives the words "illegal base64 data at input byte X" as if
they were a successful decoding. This is a longstanding API quirk
rather than a vulnerability, but it makes downstream parsing brittle
and can leak internal positions.

**Recommendation.** Return an empty string on error; provide
`mustBase64decode` for callers that care.

### L-6. `substring` can panic on inverted bounds

**File:** `strings.go:228-236`

`substring(5, 3, "hello")` reaches `s[start:end]` with `start > end`,
which panics. A historical issue (#188 era) added negative-bound
handling but the inverted-bound case is unguarded.

**Recommendation.** Clamp `end >= start`, or swap the arguments and
return `""` on inversion.

### L-7. `toJson` / `toPrettyJson` swallow marshal errors

**File:** `defaults.go:108-133`

The non-`must` variants discard `json.Marshal` errors. Marshal can fail
on unsupported types (channels, functions, NaN/Inf floats, recursive
structures) — silent empty output makes downstream debugging painful
and hides type confusion.

**Recommendation.** Already addressed by `mustToJson*`; document the
trade-off in the README.

### L-8. `fromJson` parses without depth limits

**File:** `defaults.go:95-106`

Go's `encoding/json` does not limit nesting depth by default. A template
that pipes hostile input through `fromJson` can be made to allocate
deeply-nested `map[string]interface{}` trees. In practice a renderer's
overall input-size limit will normally bound this, but the issue is
worth a doc note.

**Recommendation.** Document that `fromJson` should not be applied to
untrusted input larger than the consumer's expected payload size.

### L-9. SHA-1 still exposed via `sha1sum`

**File:** `crypto.go:50-53`

`sha1sum` is widely used for non-security checksumming (e.g. Helm chart
digests historically), so removing it would break callers. The risk is
that template authors reach for it as a "hash" without realising
SHA-1 is broken.

**Recommendation.** Add a one-line doc comment on `sha1sum` (and on the
`sha1sum` entry in the FuncMap doc table) directing callers to
`sha256sum`/`sha512sum` for any security purpose.

## 5. Dependency review

`go.sum` pins the following direct and transitive dependencies; all are
at versions current as of the audit date. None of the listed direct
dependencies has an open advisory at the pinned version that affects
sprig's call sites.

| Module                              | Pinned    | Notes |
|-------------------------------------|-----------|-------|
| `dario.cat/mergo`                   | v1.0.2    | Successor to `github.com/imdario/mergo`. Pre-1.0 versions had recursion DoS issues; v1.0.x is clean. |
| `github.com/Masterminds/goutils`    | v1.1.1    | Upgrade in sprig 3.2.1 was specifically to address [GHSA-xg2h-wx96-xgxr](https://github.com/Masterminds/goutils/security/advisories/GHSA-xg2h-wx96-xgxr) (insecure RNG in `random.go`). |
| `github.com/Masterminds/semver/v3`  | v3.4.0    | No known advisories. |
| `github.com/google/uuid`            | v1.6.0    | No known advisories. |
| `github.com/huandu/xstrings`        | v1.5.0    | No known advisories. |
| `github.com/mitchellh/copystructure`| v1.2.0    | No known advisories. Stable. |
| `github.com/shopspring/decimal`     | v1.4.0    | No known advisories. |
| `github.com/spf13/cast`             | v1.9.2    | No known advisories. |
| `golang.org/x/crypto`               | v0.40.0   | Recent advisories (CVE-2024-45337, CVE-2025-22869) are SSH-server-side; sprig only uses `bcrypt` and `scrypt`, which are not affected. |
| `gopkg.in/yaml.v3` (indirect)       | v3.0.1    | Used only by `testify`; not on production paths. |

`govulncheck` could not be run from the audit environment because
egress to `vuln.go.dev` is not permitted from the sandbox; the table
above is based on a manual review of each module's advisory page.
**Recommendation.** Run `govulncheck ./...` in CI on every push so
future advisories surface automatically.

## 6. Cross-cutting recommendations

1. **Convert panic-on-bad-input paths to error-returning variants.**
   Several finds (M-2, M-3, M-4, M-5, M-6, M-7) share the same shape:
   the convenience function panics, only the `must*` twin returns an
   error. The convenience functions should fall back to a benign value
   instead, matching the package's own stated principle that "template
   functions should not return errors unless there is no way to print
   a sensible value."
2. **Document the security model in a `SECURITY.md`.** Sprig is
   embedded in tools (notably Helm) where templates are sometimes
   rendered against attacker-influenced data. A short threat model —
   "what guarantees does sprig make / not make when its inputs are
   untrusted?" — would help downstream maintainers decide which
   functions to whitelist.
3. **Add `govulncheck` to CI.** The repo already has GitHub Actions
   under `.github/`; adding a `govulncheck ./...` step would catch
   future advisories on the dependency tree (especially
   `golang.org/x/crypto`, which historically receives advisories every
   few months).
4. **Deprecate weak primitives in v4.** `encryptAES`/`decryptAES`,
   `htpasswd HashSHA`, and `genPrivateKey "dsa"` should be marked
   deprecated in v3 docs and removed (or replaced with authenticated
   variants) in the next major release.

## 7. Methodology

The audit was performed by:

1. Reading every `.go` file in the module root and classifying its
   functions by trust boundary (does it receive attacker-controlled
   input in a typical embedding such as Helm?).
2. Tracing each cryptographic primitive end-to-end: key derivation,
   IV/nonce handling, mode of operation, authentication.
3. Searching for `panic(`, unchecked type assertions, slice expressions
   that depend on caller-supplied bounds, and unchecked errors on
   security-relevant calls.
4. Cross-referencing every dependency in `go.sum` against the upstream
   advisory database manually (the sandboxed environment did not have
   network access to `vuln.go.dev` for an automated `govulncheck` run).
5. Reading the changelog to understand prior security-relevant changes
   (notably 2.18 → 2.19's correction of the secure-random regression
   and 3.2.1's `goutils` upgrade).

Test files were read for context but not audited as production code.
No code was modified as part of this audit.
