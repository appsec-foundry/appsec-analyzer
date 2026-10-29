---
reason: Figure 1 did not show how users sign in at an OAuth or OpenID Connect provider and then reach the application with the access token that provider issued. Common client libraries were not recognized, a client known only by its issuer showed a red unauthenticated line to the provider, and several token checks at the application appeared as unknown or as no authentication.
affected_ids: [REQ-005]
compatibility: New assessments contain additional evidenced protocol steps and can change the authentication shown on existing flows, so a reassessment reports them as architecture changes. Existing flow IDs, commands and result formats stay; the new authentication fields are optional, so older saved models remain valid and are not re-derived on export or rerender. No model call, prompt input or host contact is added, and provider metadata is never fetched.
verification: Offline tests cover each supported client library and configuration form, resource-server and client-credentials setups, a provider inside the system, token checks at the application, the token-issuer link with matching and unrelated issuers, public metadata steps, and negative cases where a dependency name, a disabled configuration or an unrelated issuer adds no step or link.
---

# OAuth and OpenID Connect flows

The user reported that Figure 1a assigns authentication badly for OAuth and OpenID Connect providers, above all that the access token sent from the user's client to the application after the sign-in is not shown. The user asked for built-in support of OpenID Connect, the authorization code grant, the client credentials grant and PKCE, for any provider product and not only Keycloak, including providers that run inside the system.

REQ-005 gains one sentence. The acceptance contract names the grants, the token-issuer link, supported token checks, evidence for every step and public metadata. The wording was shown in the conversation and approved by the user before any change.

Risks raised and decisions: the recognition stays deterministic and offline, so no model cost and no data sent to models or other hosts is added. Saved results of new runs contain more flows and changed authentication. An issuer that only an environment variable supplies stays undetected and is left to the architecture analyst. The figure shows the method, not whether it is implemented correctly, for example audience or issuer checks. More lines appear between client, application and provider. A simpler variant that only corrects wrong assignments, without grants and the token link, was offered; the user chose the full change, delivered in two stages on `main`: first the recognition and corrected assignments, then the grant steps and the token link.
