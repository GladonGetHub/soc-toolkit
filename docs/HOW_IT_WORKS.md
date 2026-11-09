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
- **AlienVault OTX:** counts threat reports ("pulses") that mention the indicator. Popular safe things such as Google DNS appear in lots of reports too (malware uses them), so it takes 10+ reports to score Malicious, and OTX's own "whitelisted" flag sets the score to 0. **No reports at all means "no opinion", not "clean"**: brand-new malware and phishing sites have no reports either, so silence proves nothing.

**"It's probably fine"** (cut false positives)
- **GreyNoise:** tells you if an IP is a mass internet scanner hitting everyone, or a known business service like Google. That's background noise, not a targeted attack.
- **CIRCL hashlookup:** tells you if a file hash belongs to a known-good file, such as a genuine Windows DLL.
- **Shodan InternetDB:** lists open ports and known CVEs on an IP. That describes *exposure*, not guilt, so it only affects the verdict if Shodan tags the IP as `c2`, `malware` or `compromised`.

A score of `None` means "no data" or "no opinion", and it doesn't pull the verdict either way.

**Error handling:** if a service is down, rate-limited (429) or rejects the key (401/403), the result says so in plain English and the other sources carry on.

**Demo** returns sample answers for the IPs from the TWP Splunk project. The tests use it, because it needs no internet.

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

## 4. `config.py`: keeping keys secret, and picking the mode

API keys are like passwords. They live in a `.env` file that `.gitignore` keeps off GitHub. `load_dotenv()` reads that file when the app starts.

The same code runs in two places, and `is_public()` tells them apart with one question: *does this server have any keys?*

- **Yes: private mode.** It's your own machine. Every source with a key is switched on and there are no limits.
- **No: public mode.** It's the public website. Everyone gets the free no-key sources, and each visitor can paste their own keys into the sidebar.

Think of it like a library computer. Anyone can sit down and use the free catalogue, but to get into a paid database you log in with your own card, and you're logged out when you leave. Nobody uses the librarian's card.

Visitor keys live in `st.session_state`, which belongs to one browser tab and disappears when it closes. They're never written to disk.

The public version also has limits, 10 indicators per lookup and 50 per session, so one visitor can't use up the free services for everyone else.

## 5. `pages/1_IOC_Enrichment.py`: the screen

Streamlit turns a Python script into a web page. Every time you click something, the script runs again from the top. Two tricks handle that:

- **`@st.cache_data(ttl=3600)`** remembers each lookup for an hour, so clicking around doesn't burn your API quota. On the public site the cache is shared by all visitors, so the cache key includes a one-way fingerprint (SHA-256) of the visitor's keys. A visitor without a VirusTotal key can never be handed a result that someone else's VirusTotal key paid for. The keys themselves are passed as `_keys`; the leading underscore tells Streamlit not to store them.
- **`st.session_state`** keeps the results on screen between reruns.

The free VirusTotal key allows 4 lookups a minute, so batches bigger than 4 wait 60 seconds after every 4 lookups.

## 6. `tests/`: proving it works

`pytest` runs 63 checks (25 for Module 1, 38 for Module 2): refanging, type detection, internal ranges, de-duplication, verdict thresholds, how we read each source's response, and which sources switch on in private and public mode (including that visitor keys are ignored on a private machine). The source tests use fake responses in the same format as the real APIs, so they run without keys or internet.

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

**How do you stop people abusing the public version?**
There are no keys of mine on the server, so there's nothing of mine to steal or use up. Visitors bring their own keys, and there are limits per lookup and per session.

**What would you add next?**
Bulk import from a CSV, and saving results to a case.

---

# How Module 2 works (part 1: headers)

## The big picture

Think of an email as a letter in an envelope.

- The **From** line is what the sender wrote on the front. Anyone can write "PayPal" there, just as anyone can write "From: the King" on an envelope.
- The **Received** headers are the **postmarks**. Every mail server the email passes through stamps it, so they show the real route.
- **SPF, DKIM and DMARC** are the **security checks** the receiving mail server did on arrival, and it writes the results in the **Authentication-Results** header.

`soc_toolkit/phishing.py` reads all of this and lists what an analyst would look for by hand. It only reads the email: links aren't visited and attachments aren't opened.

## The three checks, in plain English

| Check | The question it answers | Envelope version |
|---|---|---|
| **SPF** | Is the sending server allowed to send for this domain? | Was it posted from one of the company's own post offices? |
| **DKIM** | Is the email signed, and unchanged since it was sent? | Is the wax seal intact? |
| **DMARC** | Does SPF or DKIM back up the From address the reader actually sees? | Does the seal match the name on the front, and what does the company say to do if it doesn't? |

SPF and DKIM can both pass for an attacker's *own* domain. DMARC is the one that ties them to the From address, which is why a DMARC fail scores highest.

## Why only the top Authentication-Results header counts

Headers are added from the **top down**. The receiving server adds its results above everything that arrived with the email. A phisher can put `dmarc=pass` in their own headers before sending, but it will always sit **below** the real one. So we trust only the top header, and if a lower one claims a pass that the real one doesn't, we flag it as a **fake authentication header**.

## Red flags and their points

Same scale as Module 1: **50+ Likely phishing**, **15+ Suspicious**, below that **No red flags found**. Points add up, up to a maximum of 100.

| Red flag | Points | Why it matters |
|---|---|---|
| DMARC failed | 40 | The From address isn't backed by SPF or DKIM |
| Pretends to be a brand | 35 | "PayPal" in the name, but the domain isn't PayPal's |
| Fake address in the display name | 30 | `"service@paypal.com" <alert@evil.example>`: many apps only show the name |
| SPF failed | 30 | The server isn't allowed to send for that domain |
| DKIM failed | 25 | The signature is broken: forged or changed |
| Replies go to a different domain | 25 | Classic in invoice fraud and CEO fraud: you reply to the attacker |
| Fake authentication header | 20 | Someone planted a fake "pass" |
| SPF soft fail | 15 | The domain says this server probably shouldn't send its mail |
| SPF or DKIM missing | 10 | No proof either way |
| Return-Path on a different domain | 10 | Normal for newsletters, so low on its own |

**Brand check:** the brand must be the *exact* company name in the domain. `paypal.co.uk` passes, while `paypal-account-verify.com` and `gmail.com` don't. A lookalike domain containing the brand name is one of the most common tricks, so "contains paypal" isn't good enough.

**Where it entered the internet:** the route is read from the bottom (the sender's end) up, and the first public IP is where the email entered the internet. Internal addresses such as `10.x` are skipped. That's the IP to check in Module 1.

## What headers can't tell you

A genuine, fully authenticated email can still be dangerous if the sender's real account was hacked. That's why part 2 checks the **links**, and part 3 will check the **attachments**.

## Questions an interviewer might ask

**SPF passed, so it's genuine, right?**
Not necessarily. SPF checks the hidden Return-Path domain, not the From address the reader sees. An attacker can pass SPF for their own domain. DMARC is the check that links it to the visible From.

**How can a phisher fake headers?**
They can write any header they like *before* sending, including a fake Authentication-Results. They can't control what the receiving server adds on top, which is why we trust only the top one.

**Why might a genuine email fail DMARC?**
Forwarding and mailing lists can break SPF and DKIM. That's why the tool shows the reasons, not just a score, so the analyst can judge.

---

# How Module 2 works (part 2: links)

## The big picture

Almost every phishing email wants a click. The trick is that what you **see** isn't always where a link **goes**. In HTML, a link has two parts:

```html
<a href="https://paypal-account-verify.example/login">https://www.paypal.com/myaccount</a>
       └── where it really goes ──────────────────┘ └── what you see ─────────────┘
```

Think of a shop sign that says "Bank" over the door of a different building. Your mail app shows you the sign. You'd only see the real address by hovering over the link, and on a phone you can't hover at all.

`soc_toolkit/links.py` reads the email's HTML the way a browser would, collects every link's real address and visible text, and checks each one. **No link is ever visited.**

## The checks

| Red flag | Points | Example | Why it matters |
|---|---|---|---|
| Text doesn't match where it goes | 40 | shows `paypal.com`, goes to `evil.example` | The most common phishing trick |
| "@" trick | 35 | `https://paypal.com@evil.example` | Browsers ignore everything before the @ |
| Lookalike domain | 30 | `paypa1.com`, `paypal-account-verify.com` | Made to read like a brand at a glance |
| Form inside the email | 30 | a password box in the email itself | Real companies never collect details this way |
| Link downloads a program | 25 | `invoice.pdf.exe` | Runs code when opened |
| Bare IP address | 25 | `http://203.0.113.50/login` | Genuine companies use names, not numbers |
| Disguised characters | 25 | `xn--80ak6aa92e.com` (reads as "apple.com" in Cyrillic letters) | Letters from other alphabets that look like ours |
| Shortened link | 15 | `bit.ly/3abc` | Hides the real destination |
| Not encrypted | 5 | `http://` | Not proof on its own |

Each **kind** of problem counts once per email. Ten shortened links still score 15, not 150, but the explanation says "10 links like this".

**Lookalike check.** Swapped characters are put back first (`0` becomes `o`, `1` becomes `l`, `rn` becomes `m`), so `paypa1` reads as `paypal` and `rnicrosoft` as `microsoft`. Short brand names only match as a whole word, so `ups` doesn't match `groupsales` and `apple` doesn't match `pineapple`. Real company domains such as `googleapis.com` or `amazonaws.com` are recognised as genuine.

**Newsletter trackers.** Mailing services like Mailchimp send every link through their own click counter first, so the text says the company's site but the link goes via `list-manage.com`. That's normal marketing email, so it isn't counted as a mismatch.

## Showing email text safely

The page is built with Markdown, which turns any email address or web address into a clickable link. Text from a suspicious email must never become clickable, so `display.py` defangs addresses (`service@paypal[.]com`) and links (`hxxps://...`) and stops any formatting characters. That last part matters because an attacker could put `[Click me](https://evil.example)` in their display name, hoping it shows up as a real link in the analyst's own tool.

## Questions an interviewer might ask

**How would you check a link without clicking it?**
Read the real address from the HTML, compare it with the visible text, and look the domain up in threat intelligence. Never open it on your own machine. If you must see the page, use a sandbox such as urlscan.io or an isolated VM.

**Why is a mismatched link worse than a shortened one?**
A shortener hides the destination, but plenty of genuine companies use them. A link whose text names one site but goes to another is deliberately misleading, so it scores higher.

**What did you do about false positives?**
Real company domains are recognised, newsletter trackers aren't counted as mismatches, short brand names only match whole words, and every red flag shows its reason so the analyst can judge.

---

# How Module 2 works (part 3: attachments)

## The big picture

A file's name is just the label on a parcel. Anyone can write "invoice.pdf" on a box with a program inside. What a file **really** is shows in its first few bytes, its **magic number**, like the shape of what's in the box:

| First bytes | What it really is |
|---|---|
| `%PDF` | PDF document |
| `MZ` | Windows program |
| `PK` | ZIP file (also Word, Excel and PowerPoint files, which are ZIPs inside) |
| `D0 CF 11 E0` | Old-style Office file (.doc, .xls) |
| `L 00 00 00` | Windows shortcut (.lnk) |
| `CD001` (at byte 32769) | Disk image (.iso) |

`soc_toolkit/attachments.py` reads each attachment's bytes **in memory** to find its real type, checks the name, and works out its hashes. Nothing is opened, run, unpacked or saved to disk. For ZIP files it reads only the list of names inside, the way you'd read a parcel's packing slip without opening the box.

## The checks

| Red flag | Points | Example | Why it matters |
|---|---|---|---|
| Attachment is a program | 50 | `update.exe`, `invoice.js` | Runs code the moment it's opened |
| Attachment is a shortcut | 45 | `Invoice.lnk` | A shortcut can run any command |
| Archive hides a program | 45 | `files.zip` containing `invoice.pdf.exe` | Gets the program past filters that only check the outer file |
| Double file extension | 40 | `invoice.pdf.exe` | Windows hides the last part, so you see "invoice.pdf" |
| Reversed text in the name | 40 | `invoice[hidden character]fdp.exe`, shown as `invoiceexe.pdf` | An invisible character makes "exe.pdf" display backwards |
| Office file with macros | 40 | `.docm`, or a `.docx` containing `vbaProject.bin` | The classic "Enable content" trap |
| File type disguised | 35 | `invoice.pdf` whose bytes start with `MZ` | The name lies about what the file is |
| Disk image attached | 35 | `.iso`, `.img` | Files inside often escape scanning |
| HTML file attached | 30 | `Invoice_8841.pdf.html` | Shows a fake login page from your own computer, with no link to block |
| Password-protected archive | 30 | locked `.zip`, password in the email | Email security can't look inside |
| PDF with active content | 25 | PDF containing `/JavaScript` or `/Launch` | Ordinary invoices don't need code |

As with links, each kind of problem counts once per email.

## Hashes: a file's fingerprint

A hash is worked out from every byte of a file. Change one byte and the hash changes completely, so the same hash means the same file. Malware databases such as VirusTotal and MalwareBazaar store the hashes of known malware, so you can ask "have you seen this file before?" **without anyone opening it**. That's why the page shows MD5, SHA1 and SHA256 for each attachment. SHA256 is the one to use; MD5 and SHA1 are shown because older tools still ask for them.

## Questions an interviewer might ask

**How do you know what a file really is without opening it?**
Read its first bytes, its magic number. A Windows program always starts with `MZ`, whatever it's called.

**Why are HTML attachments dangerous? They're just web pages.**
Opening one shows a page stored on your own computer. It can look exactly like a Microsoft login page, and because there's no link in the email, link filters have nothing to catch. This is often called HTML smuggling.

**Why do attackers zip files with a password?**
Email scanners can't open a locked archive, so the malware gets through. The password is usually written in the email, which is itself a warning sign.

**A user has already opened the attachment. What do you do?**
Isolate the machine from the network, check the hash in threat intelligence, look in the EDR or SIEM for what ran afterwards, reset the user's passwords if it was a fake login page, and search for the same email in other mailboxes.

---

# How Module 2 works (part 4: threat intelligence)

## The big picture

Parts 1 to 3 judge an email by **how it's built**, like a detective examining a letter for forged stamps and a fake signature. Part 4 is the detective **asking around**: has anyone seen this sender before? This website? This file?

That's what Module 1 already does, so Module 2 reuses it rather than repeating it. `soc_toolkit/email_intel.py` gathers the indicators from the email and hands them to the same 9 sources. The shared lookup code (caching, public limits, VirusTotal pacing) lives in `soc_toolkit/lookup.py`, which both pages use.

## What gets checked, and what doesn't

| Checked | Not checked |
|---|---|
| The IP where the email entered the internet | Internal addresses (10.x, 192.168.x and so on), which would leak your network layout |
| The domain of every link | Documentation IPs such as 198.51.100.x, which only appear in examples |
| The SHA256 of every attachment | Reserved test names such as `.example`, which can't exist on the internet |
| | The email itself, its text or its attachments' contents |

Only the indicators leave the machine, and only when the analyst clicks the button.

## How results change the score

| Threat intel verdict | Points | Example red flag |
|---|---|---|
| Malicious | 50 | **Sent from a known-bad IP:** AbuseIPDB, 100% abuse confidence |
| Suspicious | 20 | **Link goes to a suspicious website** |

A **known genuine file** in CIRCL's database is shown as a good sign. If nothing is known bad, the page says so, but adds that **new phishing sites often aren't listed yet**. A clean lookup isn't proof of safety; it only means nobody has reported it so far.

## Questions an interviewer might ask

**Why not just look everything up automatically?**
Every lookup tells a third party what you're investigating, and free API quotas are small. A deliberate button keeps the analyst in control of what leaves the network.

**The domain is clean in VirusTotal but the email still looks like phishing. What do you trust?**
The evidence in the email. Attackers register fresh domains for each campaign, so threat intel often lags by hours or days. A brand-new lookalike domain with no reputation is itself suspicious.

**Why do you skip internal IPs?**
Sending them out reveals how your network is laid out, and outside services know nothing about private addresses anyway.

---

# How Module 2 works (the case note)

## Why it exists

Finding phishing is half the job. The other half is writing it up so the next person (the team lead, the next shift, the incident responder) can act without redoing the analysis. `soc_toolkit/case_note.py` builds that write-up as **plain text**, so it pastes cleanly into any ticketing system.

## What's in it

| Section | What it contains |
|---|---|
| Verdict | The verdict and risk score |
| Recommended action | What to do next, matched to the verdict |
| Email | Subject, sender, Reply-To, Return-Path, recipient, date, Message-ID, SPF/DKIM/DMARC and the sending IP |
| Red flags | Every red flag with its points, area and reason, highest first |
| Indicators | Sending IP, domains, full URLs and each attachment's name, real type, SHA256 and MD5 |
| Threat intelligence | Each lookup's verdict and top finding, if the check was run |
| Analyst notes | A blank space for your own notes |

## The two rules

1. **Nothing is clickable.** Ticketing systems often turn web and email addresses into links, and someone might click one by accident. Every link, address and domain is defanged, so `paypal-account-verify.com` becomes `paypal-account-verify[.]com`.
2. **Except what you need to search with.** The Message-ID and subject are kept exactly as sent, because you'll paste them into a mailbox search (for example in Microsoft 365 Content Search) to find and remove every copy of the email. Hashes don't need defanging; they can't be clicked.

## The recommended actions

For **Likely phishing**, the steps follow a standard phishing response:
1. Don't click or open anything.
2. **Block** the sender's domain and IP at the email gateway, and the link domains at the web proxy.
3. **Search and remove** the same email from every mailbox.
4. **Check who clicked**, in proxy and endpoint logs.
5. If anyone typed a password: **reset it, end their sessions and check for new mailbox rules**. Attackers often add a rule that hides replies from the real user.

## Questions an interviewer might ask

**You've confirmed a phishing email. What do you do?**
Contain first: block the sender and links, and pull the email from every mailbox. Then scope: who received it, who clicked, who entered details. Then remediate: reset passwords, end sessions, check mailbox rules and MFA changes. Finally, write it up, which is what the case note is for.

**Why defang indicators in a ticket?**
So nobody clicks them by accident, including tools that preview links automatically.

**Why keep the Message-ID as it is?**
It's the most reliable way to find every copy of the same email across mailboxes. Changing it would break the search.
