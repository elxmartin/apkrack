# APKrack ⚡

> Automated continuous security analysis pipeline & static dashboard for Android applications.

APKrack automatically harvests target Android packages, fetches APK binaries on-the-fly, decompiles code, performs multi-engine static application security testing (SAST) and CVE scanning, encrypts findings with OpenSSL AES-256-CBC, and serves an interactive, client-side decrypted dashboard via GitHub Pages.

---

## 🏗 Architecture Workflow

```
[ Developer / Admin ]
        │
        │ 1. Git Push (Rules, Targets, Dashboard)
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ GITHUB REPOSITORY (Remote)                                              │
│                                                                         │
│  • .github/workflows/      • public/ (Dashboard, Assets, Scripts)       │
│  • .github/config/         • public/reports/ (*.enc Gzipped Findings)   │
│  • .github/scripts/        • public/status.json (Execution State)       │
└─────────────────────────────────────────────────────────────────────────┘
        │
        │ 2. Scheduled (Daily Midnight UTC) / Manual Dispatch
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ GITHUB ACTIONS RUNNER (Ubuntu Linux VM)                                  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ A. Target Harvesting                                             │   │
│  │    • Runs bbscope / fetch_targets.sh                             │   │
│  │    • Resolves direct & developer links into extracted_apps.txt   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ B. Sequential Target Engine (Zero-Disk-Bloat Loop)               │   │
│  │                                                                  │   │
│  │    [1] Check Idempotency   ──► Skip if reports already exist     │   │
│  │    [2] Update status.json  ──► Push live execution status to UI  │   │
│  │    [3] Download APK        ──► apkeep (on-demand download)       │   │
│  │    [4] Decompile Code      ──► JADX (multi-threaded, code only)  │   │
│  │    [5] Secret Scan         ──► ripgrep against rules.yml patterns│   │
│  │    [6] SAST Security Scan  ──► MobSFScan (vulnerability rules)   │   │
│  │    [7] CVE Dependency Scan ──► Trivy filesystem scan             │   │
│  │    [8] Extract Metrics     ──► CRITICAL/HIGH/MED/LOW to status   │   │
│  │    [9] Compress & Encrypt  ──► gzip | OpenSSL AES-256-CBC PBKDF2 │   │
│  │    [10] Immediate Cleanup  ──► Wipe raw APK & decompiled code    │   │
│  │    [11] Commit Encrypted   ──► git pull --rebase & push reports  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
        │
        │ 3. Automated Deployment
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ GITHUB PAGES                                                            │
│ Serves public/ static site: index.html, styles, and *.enc payloads      │
└─────────────────────────────────────────────────────────────────────────┘
        │
        │ 4. Client-Side HTTP Fetch
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ USER BROWSER (Dashboard Frontend)                                       │
│                                                                         │
│  • Polls status.json every 5s for live progress and target history      │
│  • Renders responsive Chart.js vulnerability breakdown instantly        │
│  • Filters packages in real-time with instant search input              │
│  • Clicking "Secrets", "MobSF", or "Trivy CVE" prompts decryption key   │
│  • Decrypts & decompresses payload in-memory (Web Crypto API + Gzip)    │
│  • Formats decrypted JSON and raw findings into inspectable modal       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security & Cryptography Model

All security reports committed to the repository are protected using authenticated encryption:

- **Algorithm**: AES-256-CBC with random 8-byte salt (`Salted__` header format).
- **Key Derivation**: PBKDF2 with SHA-256 and **100,000 iterations** (`openssl enc -pbkdf2 -iter 100000`).
- **Compression**: Pre-compressed with `gzip` prior to encryption to eliminate ~85% of storage space.
- **Zero Server-Side Plaintext Storage**: Raw decompiled code, temporary downloads, and raw scan outputs are deleted immediately after encryption.
- **Client-Side Decryption**: Decryption occurs entirely inside the client's browser using the native browser **Web Crypto API** (`crypto.subtle`) and the native Streams API (`DecompressionStream('gzip')`). The secret decryption key is never transmitted or stored on the server.

---

## 🚀 Key Features

1. **Multi-Engine Security Analysis**:
   - **MobSFScan**: Static analysis for Android vulnerabilities, insecure configurations, and misconfigured permissions.
   - **Trivy**: CVE vulnerability detection across third-party Java libraries and bundled app components.
   - **Ripgrep Custom Rules**: Regex-based token and API key detection powered by [`.github/config/rules.yml`](file:///.github/config/rules.yml).

2. **Resource & Disk Optimization**:
   - **Streaming Processing**: Downloads, analyzes, and deletes each APK sequentially instead of bulk-downloading hundreds of apps at once, avoiding runner disk exhaustion (`ENOSPC`).
   - **Gzip Encrypted Bundles**: Cuts git repository storage footprint from hundreds of megabytes down to ~60MB across 300+ targets.
   - **Precompiled Binary Tooling**: Uses precompiled release binaries for `apkeep` and `trivy` with caching for JADX, reducing workflow startup time to under a minute.

3. **Modern Cyberpunk UI / UX**:
   - Live runner status, active package indicator, and batch progress bar.
   - Horizontal stacked bar charts powered by **Chart.js** displaying Critical/High/Medium/Low CVE distributions.
   - Real-time client-side search and filtering.
   - Session-cached encryption key manager with easy clear/set controls.

---

## 🛠 Project Structure

```
├── .github/
│   ├── config/
│   │   └── rules.yml            # Custom regex patterns for secrets & tokens
│   ├── scripts/
│   │   ├── fetch_targets.sh     # Dynamic target extraction via bbscope
│   │   └── run_pipeline.sh      # Engine: download, scan, encrypt, clean, push
│   └── workflows/
│       └── pipeline.yml         # GitHub Actions daily schedule & runner setup
├── public/
│   ├── index.html               # Main dashboard UI
│   ├── status.json              # Live execution state and package history
│   ├── reports/                 # Encrypted & gzipped report files (*.enc)
│   └── res/
│       ├── css/
│       │   └── style.css        # Cyberpunk dark mode styling
│       └── js/
│           ├── app.js           # Polling, table filtering, and Chart.js logic
│           └── crypto.js        # Web Crypto API & Gzip decompression pipeline
├── LICENSE                      # MIT License
├── theme.json                   # Theme color palette and layout tokens
└── README.md                    # Project documentation & architecture
```

---

## ⚙️ Configuration & Setup

### 1. Repository Secrets
In your GitHub repository, navigate to **Settings** > **Secrets and variables** > **Actions** and add:

| Secret Name | Description |
| :--- | :--- |
| `REPORT_ENCRYPTION_KEY` | Strong passphrase used by OpenSSL and the browser dashboard to encrypt and decrypt analysis reports. |

### 2. Custom Secret Rules
You can customize token and secret matching regexes by editing [`.github/config/rules.yml`](file:///.github/config/rules.yml):

```yaml
rules:
  - id: google-api-key
    name: Google API Key
    pattern: 'AIza[0-9A-Za-z\-_]{35}'

  - id: aws-access-key
    name: AWS Access Key ID
    pattern: '(?:AKIA|ASIA)[0-9A-Z]{16}'
```

### 3. Running Manually
1. Go to the **Actions** tab in your GitHub repository.
2. Select **Continuous Security Pipeline**.
3. Click **Run workflow** on the `main` branch.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).