<!--
  security-architecture.example.md — STYLE ANCHOR for §6 H4 control blocks.

  Purpose
  -------
  This file is NOT a template that gets rendered. It is a style anchor the
  Stage 2 renderer agent (appsec-threat-renderer.md) Read()s before authoring
  `.fragments/security-architecture.md`. Every H4 control block in the final
  threat-model.md MUST follow the structural and linguistic patterns shown
  here. The blocks below are taken from the proven reference threat model
  for OWASP Juice Shop and represent the quality bar.

  Mandatory structure for every H4 control block (§6.2-§6.12)
  ----------------------------------------------------------
  1. `#### <Mechanism Name>` — name a real mechanism (e.g. "JWT Issuance",
     "Password Reset", "Query Construction"), NOT a taxonomy bucket
     ("JWT Authentication", "Password Hashing").
  2. **Positive intro paragraph** (≥ 25 words, 1-3 sentences) explaining
     what the mechanism IS and HOW it works in this codebase. Name the
     route, library, and components. NEVER open with "No", "None",
     "Missing", "Not implemented" — that belongs in the assessment.
  3. **Optional Mermaid `sequenceDiagram`** — include ONLY when the flow
     has ≥ 3 steps between ≥ 2 components AND prose alone would be
     unclear. Always introduce with ONE sentence ending in `:` such as
     "The diagram shows …:".
  4. `**Security assessment**` label followed by 2-4 sentences naming
     the concrete library, route, and `file:line` evidence. Multi-sentence
     prose — never a one-line `❌ Missing` tag.
  5. **Optional code excerpt** (≤ 6 lines) — include ONLY when the defect
     concentrates at one short location. Always introduce with ONE
     sentence ending in `:` such as "The vulnerable login lookup …:".
  6. `**Relevant findings**` label followed by a bullet list. Each bullet
     follows the form
     `- [F-NNN](#f-nnn) — <one sentence stating what this finding proves
     about the control>.` — never the title duplicated, never a span
     like `[F-001]…[F-005]`.

  Both Mermaid and code are OPTIONAL clarity aids. A pure-prose block
  is valid and common (see §6.8 Browser Security Headers in the
  reference). The mandatory elements are the intro paragraph, the
  assessment, and the findings bullet list.
-->

## Example 1 — Identity & Authentication, with diagram + code (the richest shape)

#### JWT Issuance

After a successful password or TOTP check, `lib/insecurity.ts:issueAuthToken()` creates a JWT containing the user’s ID, email, and role. It signs the token with the RSA private key at `lib/insecurity.ts:23` and sets a one-hour expiry. Login and two-factor verification both use this helper, so API tokens share the same format and lifetime.

The diagram shows how a verified login produces a token for the browser:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant API as Login Route
    participant Issuer as issueAuthToken()
    participant Key as RSA Private Key

    User->>API: Successful credential check
    API->>Issuer: Sign payload {id, email, role}
    Issuer->>Key: Load private key
    Key-->>Issuer: PEM bytes
    Issuer-->>API: Encoded JWT (RS256, 1h)
    API-->>User: { token, basket_id, email }
```

**Security assessment**

The token’s signature should prevent anyone else from creating a valid token. Here, the private key is committed at `lib/insecurity.ts:23`, and the older `express-jwt` verifier at `lib/insecurity.ts:57` accepts `alg:none`, which skips signature verification. Load the key from an external secret store and allow only `RS256` during verification.

The source contains the signing key:

```ts
export const privateKey =
  '-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDNwqLEe...'
```

**Relevant findings**

- [F-001](#f-001) — Hardcoded RSA private key allows offline JWT forgery without breaking signing math.
- [F-002](#f-002) — `alg:none` acceptance lets an attacker drop the signature entirely.

---

## Example 2 — Identity & Authentication, with diagram, no code

#### Password Reset

`POST /rest/user/reset-password` accepts an email address, a security-question answer, and a new password. The handler in `routes/resetPassword.ts` looks up the registered answer through `SecurityAnswers`, compares it, and updates the password. It sends no email token and applies no rate limit.

The diagram shows the intended single-step reset path:

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant SPA as Reset Form
    participant API as Reset Route
    participant DB as Users + SecurityAnswers

    User->>SPA: Enter email, security answer, new password
    SPA->>API: POST /rest/user/reset-password
    API->>DB: Lookup security answer for email
    DB-->>API: Stored answer hash
    API->>API: Compare supplied answer
    API->>DB: UPDATE Users SET password = hash(new)
    API-->>SPA: 200 OK
```

**Security assessment**

Knowing the security answer is enough to reset the password. There is no separate confirmation or rate limit, and answers use the same weak MD5 hash as passwords (`models/securityAnswer.ts:18`). Use a single-use token sent through a verified channel and limit attempts per account.

**Relevant findings**

- [F-014](#f-014) — Account takeover via guessable security answer; no rate-limit on the reset endpoint.
- [F-020](#f-020) — Unsalted MD5 weakens the answer hash that the reset relies on.

---

## Example 3 — Query Construction, no diagram, with code

#### Query Construction

Most database access uses Sequelize models in `models/`, which generate parameterized queries. Login (`routes/login.ts:34`) and search (`routes/search.ts:23`) instead build SQL strings for `models.sequelize.query()`. Review updates accept a user-supplied MarsDB selector at `routes/updateProductReviews.ts:24`, letting callers change the query’s structure.

The search route inserts the supplied search text directly into SQL:

```ts
models.sequelize.query(
  `SELECT * FROM Products WHERE (
     (name LIKE '%${criteria}%' OR description LIKE '%${criteria}%')
     AND deletedAt IS NULL
   ) ORDER BY name`
)
```

**Security assessment**

Login, search, and review updates let user input change database queries. Attackers can supply SQL or query operators that the application then executes. Pass SQL values through `?` bind parameters, and validate selectors so callers cannot alter the intended query structure.

**Relevant findings**

- [F-003](#f-003) — SQL injection in the password login query allows authentication bypass.
- [F-004](#f-004) — SQL injection in product search enables data exfiltration.
- [F-011](#f-011) — NoSQL injection via user-controlled MarsDB selector on review updates.

---

## Example 4 — Pure-prose H4 (no diagram, no code) — valid when both would just repeat what prose already states

#### Browser Security Headers

Express applies Helmet in `server.ts:81` before mounting the API router. It sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `X-DNS-Prefetch-Control: off` for all routes. The Angular development server adds no further headers.

**Security assessment**

The application omits `Content-Security-Policy`, `Strict-Transport-Security`, `Referrer-Policy`, and `Permissions-Policy`. A Content Security Policy could limit the impact of stored XSS in the search-result component. Enable the default Helmet protections and configure a policy that allows the application’s required asset sources.

**Relevant findings**

- [F-031](#f-031) — Missing Content-Security-Policy header allows uncontrolled script execution from any reachable origin.
- [F-033](#f-033) — Missing Strict-Transport-Security header leaves HTTPS downgrade attacks viable on first contact.
