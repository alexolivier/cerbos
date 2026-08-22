# Cerbos Security Audit

**Date:** 2026-08-22
**Scope:** Full codebase audit of the Cerbos policy decision point (PDP) — `internal/`, `cmd/`, and `pkg/`.
**Method:** The codebase was partitioned into six subsystems, each reviewed independently by a dedicated auditor tracing real code paths from untrusted inputs to security-relevant sinks. Every finding below the "informational" bar was re-verified against the source (and, for the parser DoS class, empirically reproduced). Dependencies were checked for currency (Go 1.26, `go-jose/v4 v4.1.4`, `x/crypto v0.55.0`, `grpc v1.83.0` — all current).

Cerbos is an authorization engine: a wrong `ALLOW`/`DENY`, or an outage of the PDP, is a direct security impact. Findings are framed accordingly.

---

## Summary

| # | Severity | Finding | Area |
|---|----------|---------|------|
| C1 | **Critical** | Self-referential YAML anchor crashes the whole process (unrecoverable) | parser |
| H1 | **High** | TLS init failure fails **open** to plaintext listeners | server |
| H2 | **High** | Default admin credentials remain fully functional; misconfig only warns | server |
| H3 | **High** | "Billion laughs" exponential YAML alias expansion (DoS) | parser |
| H4 | **High** | Deeply-nested flow collections cause O(depth²) OOM (DoS) | parser |
| M1 | Medium | Path traversal via blob object keys → symlink planting across the fleet | storage/blob |
| M2 | Medium | SSRF + local-file oracle via schema `$ref` in the unauthenticated Playground | server/schema |
| M3 | Medium | Hub audit mask silently no-ops on list-valued attributes → data shipped to cloud | audit/hub |
| M4 | Medium | Remote JWKS URL not required to be HTTPS → MITM JWT forgery | auxdata |
| M5 | Medium | Configured client-CA silently ignored if unreadable; mTLS never enforced | server |
| M6 | Medium | AWS Lambda path skips validation + panic recovery → nil-deref crash | server/awslambda |
| M7 | Medium | REST gateway has no request-body size limit (memory DoS) | server |
| M8 | Medium | Unbounded regexp cache growth from Admin API filters (DoS) | storage/db |
| M9 | Medium | Default mode fails **open** on `DENY`-condition CEL errors (intended v0.54 compat) | engine |
| L1–L17 | Low | Hardening / defense-in-depth items (see below) | various |

**No wrongful-`ALLOW` correctness bug was found in the core decision engine** — effect precedence, scope/role/derived-role resolution, glob matching, and per-request concurrency are all implemented as documented and match the shipped test suite. The critical and high-severity findings are concentrated in the **untrusted-input parsing surface** (a single crafted policy file can crash the fleet) and in **fail-open configuration defaults**.

---

## Critical

### C1 — Self-referential YAML anchor crashes the entire process (unrecoverable)

**Location:** `internal/parser/parser.go` — `resolveAlias` (523–598), `resolveNode` (494–520); `recover()` guard at `parse()` (221–226).

A YAML alias that points back into its own anchor causes unbounded mutual recursion (`resolveNode` → `resolveAlias` → `AliasNode` case → `resolveAlias` …) with no visited-set or cycle detection, terminating in a Go `fatal error: stack overflow`. Go's runtime stack overflow is **not** a recoverable panic, so no `recover()` can contain it — and in any case the alias-resolution phase runs *after* the `recover()` that only wraps `lexer.Tokenize`/`parser.Parse`.

```go
// resolveAlias, AliasNode case (parser.go:588–594)
case *ast.AliasNode:
    aliasName := nn.Value.GetToken().Value
    node, ok := u.anchors[aliasName]
    if !ok { return nil, uctx.perrorf(n, "unknown alias %s", aliasName) }
    return u.resolveAlias(uctx, node)   // no cycle/visited tracking
```

**Reproduction** — this complete 5-line policy crashes the process (verified: `runtime: goroutine stack exceeds 1000000000-byte limit … fatal error: stack overflow`):

```yaml
apiVersion: api.cerbos.dev/v1
exportConstants:
  name: c
  definitions:
    x: &a [*a]
```

**Impact:** Policies are parsed on startup and on every store reload. The disk, git, blob, and bundle loaders all feed untrusted policy YAML through this path *before* protovalidate runs, so schema validation cannot stop it. An actor who can land one file in a shared git repo / object-storage bucket takes down authorization for **every tenant** served by that instance — and the process cannot self-recover.

**Remediation:** Track visited anchors and reject cycles during alias resolution; enforce a maximum recursion depth; cap input document size. (See the shared parser remediation under H3/H4.)

---

## High

### H1 — TLS initialization failure fails open to plaintext listeners

**Location:** `internal/server/server.go:143–145`, `createListener` (272–283), `initializeTLSConfig` (221–270).

```go
if err := s.initializeTLSConfig(log); err != nil {
    log.Error("Failed to initialize TLS configuration", zap.Error(err))
}   // <-- no return; startup continues
...
if s.tlsConfig != nil {           // createListener
    l = tls.NewListener(l, s.tlsConfig)
}
```

If TLS init fails (cert/key missing, unreadable, bad permissions after a rotation, or a CA PEM that fails to append), the error is **logged and swallowed**. `s.tlsConfig` stays `nil`, and `createListener` then brings up **both gRPC and HTTP listeners in plaintext on the ports the operator configured for TLS**.

**Scenario:** A mounted secret is briefly absent or mis-permissioned at boot (common with init ordering / secret rotation). Cerbos starts anyway and serves authorization decisions and the admin API in cleartext; clients that don't strictly pin TLS send Basic-auth admin credentials and policy data over the wire. Nothing gates health on TLS actually being active.

**Remediation:** `return err` on TLS-init failure — fail closed. Refuse to open listeners when TLS was configured but `tlsConfig` is `nil`.

### H2 — Default admin credentials remain fully functional; misconfiguration only warns

**Location:** `internal/server/conf.go:22,36,42,190–195`; `internal/server/server.go:303–317,351–358`; `internal/svc/admin_svc.go:568–603`.

```go
defaultAdminPassword        = "cerbosAdmin"
defaultAdminUsername        = "cerbos"
defaultRawAdminPasswordHash = "$2y$10$VlPwcwpgcGZ5KjTaN1Pzk.vpFiQVG6F2cSWzQa9RtrNo3IacbzsEi"
```

When `adminAPI.enabled: true` but no `adminCredentials` block is supplied, `SetDefaults` installs the built-in `cerbos` / `cerbosAdmin` pair, and `checkForUnsafeAdminCredentials` only emits a **log warning** — the default credentials stay valid.

**Exploit:** An operator enables the admin API (e.g. following a tutorial) without overriding credentials. Any network client sends `Authorization: Basic Y2VyYm9zOmNlcmJvc0FkbWlu` (`cerbos:cerbosAdmin`) and gains full admin: `AddOrUpdatePolicy` / `DeletePolicy` / `DisablePolicy` / `AddOrUpdateSchema` (**total authorization bypass** for every dependent application) plus `ListAuditLogEntries` (decision-log exfiltration).

Mitigating factor: `adminAPI.enabled` defaults to `false`, so this requires the operator to enable the API — hence High rather than Critical. The blast radius, once triggered, is complete compromise.

**Remediation:** Refuse to start the admin service when it is enabled and the credential hash still matches the shipped default (fail closed instead of warn). The auth path itself is otherwise sound — `bcrypt.CompareHashAndPassword`, constant-time.

### H3 — "Billion laughs" exponential YAML alias expansion (DoS)

**Location:** `internal/parser/parser.go` — `resolveNode`/`resolveAlias` (494–598) feeding `unmarshalValue`/`unmarshalListValue`/`unmarshalStruct` (1013–1062). Landing fields `Constants.Local` / `ExportConstants.Definitions` are `map[string]*structpb.Value`, which accept arbitrarily nested lists.

Aliases are resolved with no memoization and no expansion budget, so nested anchors each referencing the previous one N times expand to Nᵈ leaves at unmarshal time.

```yaml
apiVersion: api.cerbos.dev/v1
exportConstants:
  name: bomb
  definitions:
    a0: &a0 "lol"
    a1: &a1 [*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0]
    a2: &a2 [*a1,*a1,*a1,*a1,*a1,*a1,*a1,*a1]
    # … a10 → 8^10 ≈ 1.07e9 leaves
```

**Verified timings** (fanout 8, clean exponential growth): `levels=5` → 50 ms, `levels=6` → 452 ms, `levels=7` → 5.3 s; `levels=10` (~11-line file) did not complete. Expansion occurs during unmarshalling, so validation cannot prevent it.

**Remediation:** Enforce a global expanded-node budget during alias resolution/unmarshalling.

### H4 — Deeply-nested flow collections cause O(depth²) memory blow-up (DoS)

**Location:** `internal/parser/parser.go` — recursive `unmarshalValue`/`unmarshalList`/`unmarshalMessage` plus per-node proto-path string construction in `forListItem` (1306–1310), `forField` (1294–1304), `recordFieldPosition` (1331–1341).

Each nesting level builds and stores a path string proportional to the current depth, so total memory is ~O(depth²) on top of the AST.

```yaml
apiVersion: api.cerbos.dev/v1
exportConstants:
  name: deep
  definitions:
    x: [[[[[ ... ]]]]]     # ~30000 levels deep, ~60 KB of input
```

**Verified:** at depth 30000 (~60 KB input) the process exceeded a 4 GB cap and died with `fatal error: out of memory`. Amplification is tens of thousands of times the input size.

**Remediation (shared for C1/H3/H4):** In the parser, enforce a maximum nesting depth, a global expanded-node budget, and an input-size cap; track visited anchors to reject cycles; and extend the `recover()` to wrap the unmarshalling phase so faults become graceful per-document errors instead of process faults.

---

## Medium

### M1 — Path traversal via blob object keys → symlink planting across the fleet

**Location:** `internal/storage/blob/cloner.go:76`, `internal/storage/blob/store.go:409–438`, `internal/storage/blob/fs.go:45–66`.

Object keys returned by the bucket are turned into filesystem paths with no `..`/containment check — only a leading-slash trim and an extension filter:

```go
file := strings.TrimPrefix(obj.Key, "/")            // cloner.go:76
...
src := filepath.Join(tmpDir, source)                // store.go:410 (source == object key)
s.workFS.MkdirAll(filepath.Dir(src), perm775)       // fs.go: filepath.Join(dir, path) — no containment
s.symlink.Symlink(destination, src)
```

`filepath.Join` cleans `..` segments, so an object key like `../../../../var/tmp/evil/policy.yaml` (a `*.yaml`/`*.yml`/`*.json` suffix passes `IsSupportedFileType`) escapes the work directory. On each poll, every PDP syncing the bucket creates directories and a symlink at an attacker-chosen writable path.

**Impact:** Fleet-wide creation of new symlinks/directories at arbitrary writable locations by anyone with **write access to the policy bucket** (a lower privilege than host root). Capped below High because the created object is a *symlink* to a content-addressed cache file and `os.Symlink` fails if the target exists (no overwrite of existing files), but it is a real containment break beyond `workDir`.

**Remediation:** Reject keys failing `filepath.IsLocal` / `fs.ValidPath` at ingestion in `Cloner.Clone`, before any key reaches `filepath.Join`/`os.Symlink`.

### M2 — SSRF + local-file oracle via schema `$ref` in the unauthenticated Playground

**Location:** `internal/schema/schema.go:113–121,152–216` (`DefaultResolver` → `loadHTTPURL`/`loadFileURL`); `internal/svc/playground_svc.go:283–285`.

The runtime schema manager resolves schema references through `DefaultResolver`, which fetches `http`/`https` refs via `http.DefaultClient` and opens `file://` refs from disk. The Playground compiles **attacker-supplied** policies with this same resolver, and a policy's schema `ref` is directly attacker-controlled:

```go
compiler.LoadURL = func(path string) (io.ReadCloser, error) { return m.resolver(ctx, path) }  // schema.go:117
...
case "http", "https": return loadHTTPURL(ctx, u)   // schema.go:162
case fileURLScheme:   return loadFileURL(u)        // arbitrary local path open
```

**Exploit (when `playgroundEnabled: true`, typically internet-facing):** an unauthenticated `PlaygroundValidate`/`Test`/`Evaluate` call with a resource policy whose schema ref is `http://169.254.169.254/latest/meta-data/...` triggers a server-side GET to the cloud metadata service or any internal host (SSRF). A `file://` ref turns the differentiated error messages ("schema … doesn't exist" vs. parse error) into a local-file existence oracle.

Mitigating factor: the Playground is disabled by default.

**Remediation:** For untrusted (Playground) compilation, use a resolver restricted to the in-memory `cerbos://` scheme and reject `http`/`https`/`file` refs.

### M3 — Hub audit mask silently no-ops on list-valued attributes → sensitive data shipped to cloud

**Location:** `internal/audit/hub/filter.go:494–517` (`visitStructpb`).

The Hub `mask` config strips sensitive attributes from audit entries before they are shipped to the Cerbos Hub cloud. For `structpb` **list** values, the "delete all elements" and "delete the sole element" branches assign to the local pointer `v` instead of mutating the parent container, so nothing is removed:

```go
case tokenWildcard:
    if c.children == nil { v = nil; continue }        // no-op: v is a local *structpb.Value
...
case tokenIndex:
    if c.children == nil {
        if l := len(k.ListValue.Values); idx < l {
            if l == 1 { v = nil }                      // no-op for single-element list
            else { k.ListValue.Values = slices.Delete(k.ListValue.Values, idx, idx+1) }  // works
        }
        continue
    }
```

(The `StructValue` branch uses `delete(k.StructValue.Fields, name)` and works; the multi-element list branch works — which is why this is easy to miss.)

**Scenario:** A mask such as `checkResources: ["inputs[*].principal.attr.tags[*]"]` (or `...tags[0]` on a single-element list) resolves into `visitStructpb`, hits the no-op branch, and the sensitive attribute is **transmitted to Hub despite the mask**.

**Remediation:** Mutate through the pointer (e.g. set `v.Kind` to a null value or replace the list contents) rather than reassigning the local `v`.

### M4 — Remote JWKS URL not required to be HTTPS → MITM JWT forgery

**Location:** `internal/auxdata/conf.go:106–109` (validation), `internal/auxdata/jwt.go:242–255` (registration).

Config validation only checks the remote keyset URL is non-empty; nothing rejects `http://`, and `cache.Register(ctx, src.URL)` fetches whatever is given — with no warning (unlike the other insecure toggles, which log `[INSECURE CONFIG]`).

**Scenario:** `remote.url: http://idp.internal/keys.jwks`. A MITM attacker serves their own JWKS; Cerbos then "verifies" attacker-forged JWTs as valid, and those forged claims flow into policy evaluation as trusted aux data — a full aux-data trust bypass.

**Remediation:** Reject non-HTTPS remote JWKS URLs (or at minimum warn loudly, matching the other insecure options).

> The JWT verification **core** is otherwise sound (verified against `lestrrat-go/jwx/v3 v3.2.0`): `alg:none` is rejected, RS256→HS256 key confusion is prevented, and empty/unresolved keysets fail closed.

### M5 — Configured client-CA silently ignored if unreadable; mTLS never enforced

**Location:** `internal/server/server.go:248–267`.

```go
if conf.CACert != "" {
    if _, err := os.Stat(conf.CACert); err != nil {
        return nil   // silently proceeds with NO client-cert verification
    }
    ...
    s.tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven   // never *requires* a client cert
}
```

Two issues: (a) a configured-but-unreadable `caCert` path causes the function to return success with client-cert verification **not** configured — the operator believes mTLS is active when it is not; (b) even on the happy path, `VerifyClientCertIfGiven` accepts clients presenting **no** certificate, so `caCert` gives a false impression of mutual TLS.

**Remediation:** Treat a configured-but-unreadable `caCert` as fatal; document that `caCert` does not gate access, or offer a `RequireAndVerifyClientCert` option.

### M6 — AWS Lambda path skips validation + panic recovery → nil-deref crash

**Location:** `internal/server/awslambda/router.go:20–88`, `function.go:62–88`; `internal/svc/cerbos_svc.go:90–93`.

The Lambda handler calls services directly with a JSON-unmarshalled request, **without** the `protovalidate` interceptor or the `grpc_recovery` interceptor that protect the normal server. `PlanResources` dereferences the resource unconditionally:

```go
ResourceKind:  request.Resource.Kind,          // cerbos_svc.go:92 — nil-deref if resource omitted
PolicyVersion: request.Resource.PolicyVersion,  // :93
```

**Exploit:** `POST /api/plan/resources` with body `{}` reaches line 92 and panics on the nil `Resource`; with no recovery interceptor the invocation aborts. Every malformed request forces a crash.

**Remediation:** Run `validator.Validate(req)` on the decoded request in the Lambda converters, and wrap `RouteRequest` in a `recover()`.

### M7 — REST gateway has no request-body size limit (memory DoS)

**Location:** `internal/server/server.go:461–469`, `internal/server/middleware.go` (no `MaxBytesReader`/`LimitReader` in the HTTP path).

The gRPC server caps messages at 4 MiB, but the grpc-gateway reads and JSON-unmarshals the **entire** HTTP body in-process before forwarding over loopback gRPC. The `http.Server` sets read timeouts but no body-size cap, and `maxResourcesPerRequest`/`maxActionsPerResource` limits apply only *after* the full parse.

**Exploit:** `POST /api/check/resources` with a several-hundred-MB JSON body (within the 30 s read timeout); concurrent requests drive memory exhaustion (no HTTP-side concurrency limit comparable to gRPC's `MaxConcurrentStreams`).

**Remediation:** Wrap the gateway handler with `http.MaxBytesHandler`, aligned with the gRPC receive limit.

### M8 — Unbounded regexp cache growth from Admin API filters (DoS)

**Location:** `internal/storage/db/internal/db.go:1188–1245`; backing cache `internal/util/regexp.go:14–44`; SQLite package global `internal/storage/db/sqlite3/sqlite3.go:52–79`.

`ListPolicyIDs`/`InspectPolicies` compile the `NameRegexp`/`ScopeRegexp`/`VersionRegexp` request fields through a process-lifetime cache that is **never evicted and has no size bound**:

```go
func (c *RegexpCache) GetCompiledExpr(re string) (*regexp.Regexp, error) {
    ...
    c.cache[re] = r   // grows without bound
}
```

An authenticated Admin-API caller issuing many unique regexps grows the map indefinitely → memory-exhaustion DoS. (Patterns are RE2, so there is no catastrophic-backtracking risk — only unbounded retention.)

**Remediation:** Bound the cache (LRU/size cap) or compile per-request without caching arbitrary user input.

### M9 — Default mode fails *open* on `DENY`-condition CEL errors

**Location:** `internal/ruletable/check.go:823–837` (`evaluateCELExprToRaw`), `368–413`.

When a rule condition raises a CEL runtime error (missing attribute, type mismatch) and `strictEvaluation` is off (**the default**), the error is swallowed and the condition is treated as **false**:

```go
if celtypes.IsError(result) {
    ec.celErrors.Add(ctx, expr.Original, err)
    if ec.StrictEvaluation { return nil, evaluator.StrictEvaluationError{...} }
    return nil, nil          // non-strict: error becomes "no value"
}
```

A `EFFECT_DENY` rule whose condition errors is therefore silently skipped, and a wildcard/other `ALLOW` can then grant the request.

**Scenario:** `view → roles:["*"]` ALLOW plus `view → roles:["user"]` DENY with condition `R.attr.secret == "x"`. A `user` request for a resource *without* `attr.secret` errors the DENY condition → the DENY is dropped → **ALLOW**. Confirmed by the project's own test `internal/ruletable/cel_errors_test.go:167` (`erroring_deny_fails_open_and_is_reported` → asserts `EFFECT_ALLOW`, comment "fail-open preserved in v0.54"); the Plan path mirrors it (`:249`).

**Assessment:** This is *intended, tested* v0.54-compatibility behavior, mitigated by `engine.strictEvaluation: true` (which fails the action closed) and surfaced in audit logs. It is flagged because it is the default, it silently bypasses an explicit `DENY`, and operators on this build should not assume `DENY`-fail-closed is in effect (the fail-closed change is slated for v0.55).

---

## Low / hardening

- **L1 — CORS defaults to allow-all origins** (`internal/server/middleware.go:150–189`, `conf.go:90–99`). CORS is on by default with an empty `AllowedOrigins`, which rs/cors reflects as allow-all. Limited impact (API uses `Authorization` header, not cookies; `AllowCredentials` unset), but an insecure default. *Fix:* default to no CORS / require an explicit allowlist.
- **L2 — AuthZen metadata reflects attacker-controlled `Host`/`Proto` headers** (`internal/svc/authzen_svc.go:670–695`). The unauthenticated `/.well-known/authzen-configuration` echoes `X-Forwarded-Host`/`X-Forwarded-Proto` into advertised URLs. Host-header-injection / cache-poisoning class. *Fix:* derive the base URL from config or an allowlist.
- **L3 — Admin Basic-auth parsing quirks** (`internal/svc/admin_svc.go:583–600`). `bytes.Split(..., ":")` with `len != 2` rejects any password containing `:`, and `TrimSpace` strips surrounding whitespace from the secret — silently blocking strong passwords. *Fix:* use `bytes.SplitN(decoded, sep, 2)` and don't trim the secret.
- **L4 — `namer.sanitize` collapses distinct names to one module ID** (`internal/namer/namer.go:17–20,213–218`). For legacy-pattern names, `foo-bar`, `foo/bar`, `foo@bar`, `foo_bar` all sanitize to `foo_bar` → same FQN/`ModuleID`, so two policies can collide and one silently shadows the other (misroutes authorization). Documented back-compat behavior. *Fix:* warn at compile time when two distinct source names sanitize to one FQN.
- **L5 — 64-bit non-cryptographic module IDs** (`internal/namer/namer.go:54–56`, `internal/util/hash.go:30–32`). Policy identity is a single 64-bit xxHash of the FQN, with no collision detection. A targeted second-preimage is ~2⁶⁴ (not practical today), so informational, but there is no cryptographic margin.
- **L6 — Audit call IDs use `math/rand`** (`internal/audit/id.go:17,90–103`). ULID entropy is drawn from `math/rand` seeded with wall-clock time, so `cerbos_call_id` values (audit-lookup keys, returned to clients) are predictable. Low impact (reading audit entries requires admin access); note `audit/context.go` correctly uses `crypto/rand`. *Fix:* use `crypto/rand` entropy.
- **L7 — Symlink following in disk/git loaders** (`internal/storage/disk/disk.go:71`, `internal/storage/git/store.go:325`). Both build the index over `os.DirFS`, which is not a symlink boundary; a symlinked file with a policy extension inside the tree is opened and parsed. Low (target must parse as a valid policy; contents aren't echoed back). *Fix:* traverse via `os.Root`.
- **L8 — S3 endpoint TLS disableable via bucket-URL query** (`internal/storage/blob/store.go:153–156`). `disable_https` in the bucket URL turns off TLS to the object store (operator config, but a footgun — policy bundles then transit in cleartext). *Fix:* doc warning / restrict to non-production.
- **L9 — `file` audit backend has effectively no default rotation/retention** (`internal/audit/file/log.go:62–71`). Without an explicit `logRotation` block, the rotator uses `MaxSize: math.MaxInt32` and unbounded age/backups → unbounded audit-log growth can fill the disk. Contrast the `local` badger backend's 1h–30d TTL. *Fix:* sane default `MaxSize`/`MaxAge`.
- **L10 — World-readable permissions on policy exports** (`cmd/cerbosctl/store/export/internal/exporter.go:25,29,243,247`). Uses `os.ModePerm` (0777) dirs / `os.Create` (0666) files, inconsistent with the download path's `0o700`. Exported bundles encode authorization logic. *Fix:* `0o700`/`0o600`.
- **L11 — REPL history dir created 0744** (`cmd/cerbos/repl/repl.go:64,109`). History (holding evaluated principal/resource attributes) is world-readable. *Fix:* `0o700`/`0o600`.
- **L12 — `cerbosctl … --tls-insecure` disables verification with no warning** (`cmd/cerbosctl/hub/auth/auth.go:73–75`, `hub/store/store.go:82–84`). Silently skips verification against `api.cerbos.cloud` while carrying client credentials; inconsistent with the PDP→Hub path, which logs `[INSECURE CONFIG]`. *Fix:* emit the same warning.
- **L13 — Telemetry send-on-closed-channel race at shutdown** (`internal/telemetry/telemetry.go:259–286`). `Report` can send into `eventChan` after `Stop` closes it, panicking on the (no-`recover`) tally goroutine. Shutdown-only. *Fix:* guard with a done signal / `sync.Once`.
- **L14 — JWT `exp`/`aud`/`iss` not enforced centrally** (`internal/auxdata/jwt.go:115–148,181–195`). A validly-signed token with **no** `exp` is accepted indefinitely; audience/issuer are never checked (the `InvalidAudience`/`InvalidIssuer` branches are dead code). Matches the documented model (policies assert these), but there is no central knob and operators may assume otherwise. Informational. *Fix:* offer required-claim / audience / issuer config.
- **L15 — JWT claim value logged on conversion failure** (`internal/auxdata/jwt.go:166–170`). A claim value failing `structpb` conversion is logged at Warn via `zap.Any("value", v)`. Rare in practice; structured logging avoids injection. *Fix:* log only the value's type.
- **L16 — Principal policies skipped when a principal has zero roles** (`internal/ruletable/check.go:188–449`). Principal-policy evaluation is nested inside the roles loop, so an empty `Roles` skips role-agnostic principal rules. Not reachable via the validated API (`roles` is `min_items:1`), and the effect is fail-closed. Informational robustness gap.
- **L17 — Non-atomic incremental policy update window** (`internal/ruletable/manager.go:125–180`). `deletePolicy` and `addPolicy` take the write lock separately, so a `Check` landing between them sees the policy absent → default DENY. Only ever a *transient over-denial* (fail-closed). *Fix:* perform the delete+re-add under one critical section.

---

## Areas reviewed and found sound

- **Core decision engine** (`internal/ruletable/check.go`, `internal/engine`): deny-overrides-within-role / permit-overrides-across-roles precedence, scope chains (`OVERRIDE_PARENT` / `REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS`), derived-role resolution, and glob action/role/resource matching all match the documentation and shipped tests. No wrongful-`ALLOW` path found.
- **Concurrency:** production `Check`/`Plan` run under an `RWMutex` with atomic index swaps on reload; `ProgramCache` and per-request caches are correctly scoped. No data races or TOCTOU rising to a security finding.
- **SQL layer** (`internal/storage/db`): all queries use `goqu` with constant identifiers and parameterized values; the one hand-written statement (`PurgeRevisions`) is static with a bound parameter. No SQL injection.
- **CEL standard library** (`internal/conditions/cerbos_lib.go`): set/path/IP/time helpers correct; `pathHasPrefix`/`crosspath` avoid the `/foo` vs `/foobar` prefix-boundary bug.
- **JWT signature core, gateway-spoofing control, telemetry payloads:** `alg:none` and key-confusion rejected; the `x-cerbos-set-by-grpc-gateway` marker is a per-process `crypto/rand` secret compared with `subtle.ConstantTimeCompare`; telemetry sends only anonymous aggregates and honors `DO_NOT_TRACK`/`CERBOS_NO_TELEMETRY`.
- **Compiler variable/constant resolution** (`internal/compile`): self-reference, cycles, undefined refs, and duplicate/ambiguous derived roles are all hard compile errors; enum injection is caught by protovalidate.
- **Store download zip-slip defense** (`cmd/cerbosctl/hub/store/download.go`): server-supplied paths are confined via `os.Root`; git operations use the `go-git` library (no shelling out).

---

## Prioritized remediation

1. **Harden the parser (C1, H3, H4)** — one change set (visited-anchor cycle detection, depth cap, expanded-node budget, input-size limit, `recover()` extended over unmarshalling) converts three whole-process DoS vectors, one an unrecoverable crash from a 5-line file, into graceful per-document errors. Highest value.
2. **Fail closed on TLS/credential misconfiguration (H1, H2, M5)** — `return` on TLS-init failure, refuse to start with default admin credentials, and treat an unreadable `caCert` as fatal.
3. **Constrain untrusted-input surfaces (M2, M7, M8)** — restrict Playground schema resolution to `cerbos://`, add an HTTP body-size cap, and bound the regexp cache.
4. **Fix the silent data-loss / data-leak bugs (M3, M4)** — correct the Hub list-mask no-op and require HTTPS for remote JWKS.
5. **Operator awareness (M9)** — document that the default build fails *open* on `DENY`-condition CEL errors, and recommend `strictEvaluation: true` for deny-sensitive deployments.
