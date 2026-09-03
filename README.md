# apkrack

```yml
[ Developer / Admin ]
        │
        │ 1. Git Push (Code & Targets)
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ GITHUB REPOSITORY (Remote)                                              │
│                                                                         │
│  • Workflows & Scripts     • public/index.html (Dashboard Frontend)   │
│  • targets.txt             • public/reports/ (Encrypted Output)       │
│                            • public/status.json (Live Execution Data) │
└─────────────────────────────────────────────────────────────────────────┘
        │
        │ 2. Triggers Daily / Manual Run
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ GITHUB ACTIONS RUNNER (Ubuntu Linux VM)                                  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ A. Fetch Targets                                                 │   │
│  │    • Runs bbscope / fetch_targets.sh                             │   │
│  │    • Outputs target package list                                 │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ B. Sequential Target Loop (Repeats per Package, zero disk bloat)  │   │
│  │                                                                  │   │
│  │    [1] Update status.json ──► Push to main (live UI status)      │   │
│  │    [2] Download APK       ──► apkeep (on-demand)                 │   │
│  │    [3] Decompile App      ──► JADX (resources omitted)           │   │
│  │    [4] Security Scan      ──► MobSFScan + Secret Regex           │   │
│  │    [5] Encrypt Reports    ──► OpenSSL AES-256-CBC PBKDF2         │   │
│  │    [6] Clean Up Disk      ──► Delete APK binary & decompiled/    │   │
│  │    [7] Push Encrypted     ──► Commit .enc reports to repo        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
        │
        │ 3. Hosts Static Dashboard Files
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ GITHUB PAGES                                                            │
│ Serves public/ index.html, status.json, and encrypted .enc reports      │
└─────────────────────────────────────────────────────────────────────────┘
        │
        │ 4. HTTP Fetch
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ USER BROWSER (Client-Side)                                              │
│                                                                         │
│  • Polls status.json to render live progress and searchable history     │
│  • User clicks "View Report" ──► Prompts / loads session key            │
│  • Fetches raw .enc payload                                             │
│  • Decrypts payload in-memory using Web Crypto API (SubtleCrypto PBKDF2)│
│  • Displays plain JSON / secrets inside modal                           │
└─────────────────────────────────────────────────────────────────────────┘

```