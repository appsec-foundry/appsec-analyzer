## 10. Mitigation Register

Changes are ordered by priority: P1 before deployment, P2 this sprint, P3 next quarter, P4 backlog. Each entry links its findings and gives the available implementation steps and checks.

### P1 — Immediate

<a id="m-001"></a>
#### M-001 — Parameterize product search

**Addresses:**

- [F-001](#f-001) — SQL injection in product search

**Prevents CWEs:**

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL Injection

**Priority:** P1 — Immediate · **Effort:** Low · **File:** `routes/search.ts:23`

**How:**

1. Bind the search term as a query parameter.

_Example implementation in `routes/search.ts:23`: it applies **Parameterize product search**._

```typescript
return findProducts(term);
```

**Verification:** Confirm injection input returns no account records.

---

### P2 — This Sprint

_No P2 mitigations._

### P3 — Next Quarter

<a id="m-002"></a>
#### M-002 — Review the remaining query paths

**Addresses:**

- [F-001](#f-001) — SQL injection in product search

**Priority:** P3 — Next Quarter · **Effort:** Low · **File:** `routes/search.ts:23`

**How:** The remaining route guards were not examined.

---

### P4 — Backlog

_No P4 mitigations._
