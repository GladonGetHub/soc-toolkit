# How Module 1 works

A plain-English tour of the code, in the order the data flows through it.

## The big picture

Think of the module as a mail room:

1. **Sorting** (`ioc.py`): letters arrive in a messy pile. We clean them up and sort them by type.
2. **Asking around** (`sources.py`): for each letter, we ask the experts who know about that type.
3. **Deciding** (`enrich.py`, `verdict`): we combine their answers into one word.
4. **Showing** (`pages/1_IOC_Enrichment.py`): we lay the results out on screen and let you export them.

```
pasted text ─► parse_iocs() ─► sources ─► verdict() ─► table + CSV
                 (ioc.py)     (sources.py)  (enrich.py)
```

## 1. `soc_toolkit/ioc.py`: cleaning and sorting

**`refang()`** undoes defanging. Analysts write `194[.]165[.]16[.]11` so nobody clicks it by accident; the APIs need the real value back.

**`detect_type()`** decides what each indicator is, in this order:
- Does Python's `ipaddress` library accept it? Then it's an **IP**.
- Does it start with `http://` or `https://`? Then it's a **URL**.
- Is it only hex characters (0-9, a-f) of length 32, 40 or 64? Then it's an **MD5, SHA1 or SHA256** hash.
- Does it look like `name.tld`? Then it's a **domain**.

The order matters. A hash is also "just letters and numbers", so we check the strict patterns first.

**`is_private_ip()`** spots internal addresses. We never send those to outside services, because that would leak information about your network and the services know nothing about them anyway. We list the ranges ourselves because Python's built-in check also treats documentation ranges like `203.0.113.0/24` as private, and those often appear in attack examples.

**`parse_iocs()`** splits the pasted text on new lines, commas, spaces or semicolons, refangs each piece, detects its type and removes duplicates.

## 2. `soc_toolkit/sources.py`: asking the experts

Each source is a small class with the same shape: a `name`, a `supports` set (which IOC types it can check) and a `lookup()` method that returns a `Result` with a 0-100 score. Because they all look alike, adding a source means writing one class and listing it in `config.py`. Nothing else changes. That's how this module grew from 2 sources to 9 without changing how the page asks them.

Think of the sources as three kinds of witness:

**"I know it's bad"** (give high scores)
- **VirusTotal:** runs the indicator past ~90 security engines. We read how many said malicious and scale it to 0-100; even a handful agreeing is a strong signal, so 15 of 90 engines gives 50.
- **AbuseIPDB:** community reports of abusive IPs. It already gives a 0-100 confidence score, so we use it as it is.
- **MalwareBazaar, URLhaus, ThreatFox** (abuse.ch, one key): curated lists of known malware samples, malware download sites and attacker servers. Being listed at all is strong evidence, so they score high. ThreatFox stores IPs as `ip:port`, so we check the IP part matches exactly; otherwise `1.2.3.4` would wrongly match `1.2.3.45`.

**"People have written about it"**
- **AlienVault OTX:** counts threat reports ("pulses") that mention the indicator. Popular safe things such as Google DNS appear in lots of reports too (malware uses them), so it takes 10+ reports to score Malicious, and OTX's own "whitelisted" flag sets the score to 0.

**"It's probably fine"** (cut false positives)
- **GreyNoise:** tells you if an IP is a mass internet scanner hitting everyone, or a known business service like Google. That's background noise, not a targeted attack.
- **CIRCL hashlookup:** tells you if a file hash belongs to a known-good file, such as a genuine Windows DLL.
- **Shodan InternetDB:** lists open ports and known CVEs on an IP. That describes *exposure*, not guilt, so it only affects the verdict if Shodan tags the IP as `c2`, `malware` or `compromised`.

A score of `None` means "no data" or "no opinion", and it doesn't pull the verdict either way.

**Error handling:** if a service is down, rate-limited (429) or rejects the key (401/403), the result says so in plain English and the other sources carry on.

**Demo** returns sample answers for the IPs from the TWP Splunk project, so the app works before you have keys.

## 3. `verdict()`: one word per indicator

The highest score from any source wins:

The page also shows **"Flagged by: 3 of 5"**: how many sources scored it Malicious, out of those that had an opinion. One source shouting is worth checking; five agreeing is near-certain.

| Score | Verdict |
|---|---|
| 50 or more | 🔴 Malicious |
| 15 to 49 | 🟠 Suspicious |
| under 15 | 🟢 Clean |
| no data | ⚪ Unknown |
| internal IP | 🔵 Internal |

Why the highest and not the average? If one trusted source says "this is a known C2 server", an average with two "no data" answers would hide it. In a SOC you'd rather check a false alarm than miss a real one.

## 4. `config.py`: keeping keys secret

API keys are like passwords. They live in a `.env` file that `.gitignore` keeps off GitHub. `load_dotenv()` reads that file when the app starts. No keys means demo mode.

## 5. `pages/1_IOC_Enrichment.py`: the screen

Streamlit turns a Python script into a web page. Every time you click something, the script runs again from the top. Two tricks handle that:

- **`@st.cache_data(ttl=3600)`** remembers each lookup for an hour, so clicking around doesn't burn your API quota.
- **`st.session_state`** keeps the results on screen between reruns.

The free VirusTotal key allows 4 lookups a minute, so batches bigger than 4 wait 60 seconds after every 4 lookups.

## 6. `tests/`: proving it works

`pytest` runs 20 checks: refanging, type detection, internal ranges, de-duplication, verdict thresholds, demo mode, and how we read each source's response. The source tests use fake responses in the same format as the real APIs, so they run without keys or internet.

## Questions an interviewer might ask

**Why not send internal IPs to VirusTotal?**
It leaks your network layout to a third party, and the services know nothing about private addresses anyway.

**Why does the highest score win instead of the average?**
Missing a real threat costs far more than checking a false alarm.

**How do you handle API rate limits?**
Results are cached for an hour, and large batches are paced to 4 lookups a minute.

**Why include sources that mostly say "it's fine"?**
False positives waste analyst time. GreyNoise and CIRCL help you close noise quickly, so time goes to real threats.

**What if two sources disagree?**
The highest score wins, and the "flagged by" count shows how strong the agreement is. The analyst then opens the details to judge.

**What would you add next?**
Bulk import from a CSV, and saving results to a case.
