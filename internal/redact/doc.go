// Package redact removes secret values from a *model.Result before it leaves
// the deterministic core of Keelix. It runs unconditionally in the engine
// (it is NOT a paid feature and NOT a registered check) so that no downstream
// consumer — the AI prompt builder, the rendered report, the public /share
// page, the stored raw scan JSON, or alert emails — ever sees a real secret.
//
// # What gets redacted (the spec)
//
// Free-text Finding fields that a check may have populated from interpolated
// .env values:
//   - Finding.Detail
//   - Finding.Evidence
//   - Finding.Resource
//   - Finding.Title          (defensive; checks rarely interpolate here)
//   - every value in Finding.Metadata
//   - Finding.Fix.Summary, Finding.Fix.Diff, and each Finding.Fix.Commands entry
//
// Result-level free text:
//   - Result.AISummary       (defensive; AI runs AFTER redaction so this is
//     normally already clean, but scrubbed for safety)
//
// Probe-derived free text (banners can echo back a secret a misconfigured
// service prints):
//   - ProbeResult.Reachable[*].Banner
//
// # What patterns count as a secret value
//
//  1. KNOWN VALUES: any literal value that appears in Stack.Env whose KEY
//     matches intel.IsSecretEnvName (password/token/api_key/secret/jwt/dsn/...).
//     This is the highest-signal rule: we know the exact bytes are a secret, so
//     we replace every occurrence of that exact substring.
//  2. CONNECTION STRINGS: substrings matching scheme://user:PASSWORD@host  — the
//     password segment is replaced. (postgres://, mysql://, redis://, mongodb://,
//     amqp://, and the generic user:pass@host form.)
//  3. BEARER / JWT: "Bearer <token>" and bare JWTs (three base64url segments
//     separated by dots, header starts eyJ).
//  4. HIGH-ENTROPY TOKENS: standalone tokens >= 24 chars drawn from
//     [A-Za-z0-9_\-+/=] with Shannon entropy >= 3.5 bits/char (catches API keys
//     not tied to a known env key, e.g. sk-..., AKIA..., gh[ps]_...).
//
// # Redaction marker
//
// A redacted span is replaced with the literal string "[REDACTED]". A
// connection-string password becomes scheme://user:[REDACTED]@host so the
// finding still reads naturally.
//
// # Non-goals
//
//   - We do NOT redact env KEY names (knowing POSTGRES_PASSWORD exists is not a
//     leak; the SEC checks already emit only key names — see SEC001).
//   - We do NOT attempt to redact secrets we have never seen and that do not
//     look like tokens (e.g. a 6-char password "secret" — covered only by the
//     KNOWN VALUES rule when it is in Stack.Env).
//   - Redaction is best-effort defense in depth; the SEC checks remain the
//     primary control that stops literal secrets from being emitted at all.
package redact
