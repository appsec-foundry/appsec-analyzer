# Verification item fixtures

Each directory holds code for one verification item in `data/test-cases.yaml`: `vulnerable/` contains the weakness the item asks about, and `safe/` builds the same feature without it. The code has no comments about the weakness, so a model that reads it gets no hint. The table below names what each pair shows.

`tests/test_case_fixtures.py` requires a pair for every item of an aspect that a depth in `data/assessment-depths.yaml` verifies. Without a model, it checks that the item applies to both variants by its own signal and that the vulnerable code gives the item candidates where the item names starting point facts. It does not check whether the model tells the variants apart; that needs a recorded-response evaluation, which does not exist yet.

When a depth starts to verify another aspect, add a pair for each of its items.

| Item | `vulnerable/` | `safe/` |
| --- | --- | --- |
| TC-AUTHN-02 | Decodes the bearer token without verifying it. | Verifies the token with RS256 and a server-held key. |
| TC-AUTHN-03 | Verifies the token but ignores its expiry and checks no issuer or audience. | Checks issuer, audience, and a maximum age. |
| TC-AUTHN-04 | Stores an unsalted MD5 hash and accepts any password length. | Requires 12 to 128 characters and stores a bcrypt hash. |
| TC-AUTHN-05 | Login names unknown accounts; a password change needs no current password; nothing limits attempts. | One message for both failures; a password change checks the current password; both routes limit attempts. |
| TC-AUTHN-06 | Hand-built implicit flow without state, with the redirect target from the query. | Authorization code flow with PKCE, state, nonce, and a fixed callback. |
| TC-AUTHN-07 | API key in the query string over plain HTTP. | Basic authentication only over HTTPS, compared in constant time. |
| TC-AUTHN-08 | A payment webhook trusts the request body without a signature check. | The provider's library checks the signature over the raw body, and the server refuses to start without the secret. |
| TC-SESSION-01 | Session cookie readable by scripts, sent over HTTP, valid for 30 days; login keeps the old session ID and logout keeps the session. | HttpOnly, Secure, and SameSite cookie with a short lifetime; login issues a new session ID and logout destroys the session. |
| TC-SESSION-02 | A form post changes the e-mail address with a `SameSite=None` session cookie and no token or origin check. | `SameSite=Strict` cookie, and state-changing requests from another origin are refused. |
| TC-AUTHZ-01 | Reads an order by ID without checking its owner. | Reads the order only together with the caller's user ID. |
| TC-AUTHZ-02 | Deletes users for any logged-in caller; serves a heap dump without authentication. | Both routes require a role. |
| TC-AUTHZ-03 | Writes the whole request body to the caller's user record. | Writes only an allow-list of profile fields. |
| TC-AUTHZ-04 | Takes the tenant ID from a request header. | Takes the tenant ID from the session. |
| TC-AUTHZ-05 | The client shows the delete button only to admins; the server lets any logged-in caller delete. | The server requires the admin role too. |
| TC-AUTHZ-06 | A query parameter selects whose invoices are listed. | Lists only the caller's invoices. |
| TC-INPUT-01 | Builds a SQL query with an f-string (Flask). | Binds the search term as a parameter. |
| TC-INPUT-02 | Passes a JSON body value into a MongoDB filter, so it can carry an operator. | Requires a string and matches it with `$eq`. |
| TC-INPUT-03 | Concatenates the host into a shell command. | Validates an IP address and runs `ping` without a shell. |
| TC-INPUT-04 | Writes a query parameter into `innerHTML`. | Writes it into `textContent`. |
| TC-INPUT-05 | Fetches any URL from the query string. | Fetches only HTTPS URLs on allowed hosts and refuses redirects. |
| TC-INPUT-06 | Parses XML with entity substitution enabled. | Disables entity substitution, network access, and DTD loading. |
| TC-INPUT-07 | Evaluates an expression from the request body. | Calculates with an allow-list of operations on numbers. |
| TC-FILE-01 | Joins a file name from the query to the reports directory (Flask). | Serves the file with `send_from_directory`. |
| TC-FILE-02 | Keeps the uploaded file under its original name without type or size limits. | Limits size and type and stores the file under a random name. |
| TC-DATA-01 | Returns the whole user record. | Returns only public profile fields. |
| TC-DATA-02 | Keeps the session token and full card data in `localStorage`. | Keeps the session in a cookie and sends the card to the provider as a token. |
| TC-DATA-03 | Signs sessions with a secret written in the code. | Reads the secret from the environment and refuses to start without it. |
| TC-DATA-04 | Turns off certificate checks and sends the API key in the URL over a plain HTTP listener. | Sends the key in a header and serves HTTPS with HSTS. |
| TC-DATA-05 | Logs payment bodies and returns stack traces and the request body on errors. | Stores and logs only needed fields and returns a reference on errors. |
| TC-AI-01 | Ticket text can make the model refund any order, and the refund runs at once. | The model can only propose a refund for the ticket's own customer, and staff approve it. |
| TC-AI-02 | Inserts the model's answer into HTML unescaped. | Escapes the answer. |
| TC-AI-03 | Reads any document the model names. | Accepts only the expected tool and reads only the caller's documents. |
| TC-AI-04 | Retrieves notes of all users for the prompt (Flask). | Filters retrieval by the caller's ID. |
| TC-AI-05 | The system prompt holds a coupon code that the model hands out on request (Flask). | The prompt holds no coupon, and the checkout grants discounts. |
