# Workspace authentication and metadata protection

The dashboard uses a Cloudflare Worker for authentication. No username, password,
password hash, session secret, or report encryption key is stored in the browser
source, Git repository, or GitHub Pages artifact.

Configure these Worker secrets before deploying `worker.js`:

| Secret | Purpose |
| --- | --- |
| `DASHBOARD_USERNAME` | The private username to permit. |
| `DASHBOARD_PASSWORD_HASH` | A PBKDF2-SHA-256 password verifier; never store the password itself. |
| `AUTH_SESSION_SECRET` | A long, random secret used to sign browser session tokens. |

Configure these non-secret Worker variables for the deployment:

| Variable | Example value |
| --- | --- |
| `DASHBOARD_ORIGIN` | The exact GitHub Pages origin, such as `https://example.github.io`. |
| `PUBLIC_SITE_ORIGIN` | The full Pages site URL, such as `https://example.github.io/repository`. |

They are set in `wrangler.jsonc` for the current Pages site. Update them if the
Pages origin or repository path changes.

`DASHBOARD_PASSWORD_HASH` must have this form:

```
pbkdf2-sha256$310000$base64-salt$base64-derived-key
```

Generate the salt with a cryptographically secure random generator, derive a
32-byte key from the password with PBKDF2-HMAC-SHA-256 and 310,000 iterations,
then store only that formatted verifier as the Worker secret. Do not put the
username, password, verifier, session secret, or report key in a committed file.

Set each secret interactively with Wrangler, so the value never appears in shell
history or a command line. Deploy only after all three secrets have been set.

On sign-in, the browser sends credentials only to the Worker over HTTPS. The
Worker compares the PBKDF2 verifier and returns an HMAC-SHA-256 signed, opaque
session token that expires after eight hours. The token remains only in
`sessionStorage` and is discarded on logout or when the tab session ends.

The pipeline encrypts `status.enc` with the existing report encryption key and
uses a keyed HMAC-derived identifier for each report directory. After the next
successful pipeline run, it removes `public/status.json` and migrates legacy
package-named report folders to opaque IDs. Do not deploy the changed frontend
until that migration run has succeeded; otherwise the old public metadata remains
exposed and the new dashboard intentionally cannot load it.
