from flask import Flask, render_template, request, jsonify
import sqlite3, json, re, socket, ssl, ipaddress, time
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
import requests

app = Flask(__name__)
DB = "scan_history.db"
TIMEOUT = 6
MAX_REDIRECTS = 4
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rebrand.ly"}
SUSPICIOUS_WORDS = {"login","verify","account","update","secure","password","banking","confirm","wallet","signin","support","urgent"}

def db():
    con=sqlite3.connect(DB)
    con.row_factory=sqlite3.Row
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, score INTEGER,
        level TEXT, findings TEXT, scanned_at TEXT)""")
    return con

def normalize_url(raw):
    raw=(raw or "").strip()
    if not raw: raise ValueError("Enter a URL to analyze.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",raw):
        raw="https://"+raw
    p=urlparse(raw)
    if p.scheme not in ("http","https"): raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not p.hostname: raise ValueError("The URL does not contain a valid hostname.")
    if p.username or p.password: raise ValueError("URLs containing embedded credentials are not allowed.")
    return raw,p

def safe_public_host(host):
    try:
        ip=ipaddress.ip_address(host)
        if not ip.is_global: return False, "Private or non-public IP address blocked."
        return True, None
    except ValueError: pass
    try:
        addresses=socket.getaddrinfo(host,None)
        for item in addresses:
            ip=ipaddress.ip_address(item[4][0])
            if not ip.is_global: return False, "Hostname resolves to a private or non-public address; request blocked."
        return bool(addresses), None
    except Exception:
        return True, "DNS lookup unavailable; live checks may be incomplete."

def inspect_certificate(host,port=443):
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as secure:
                cert=secure.getpeercert()
                expiry=cert.get("notAfter","Unknown")
                return {"valid_connection":True,"expires":expiry}
    except Exception as e:
        return {"valid_connection":False,"error":str(e)[:180]}

def analyze(raw):
    url,p=normalize_url(raw)
    host=(p.hostname or "").lower().strip(".")
    findings=[]
    score=0
    def flag(points,title,detail):
        nonlocal score
        score+=points
        findings.append({"points":points,"title":title,"detail":detail})

    if p.scheme=="http": flag(15,"Unencrypted HTTP","The connection does not use HTTPS.")
    if len(url)>100: flag(8,"Very long URL","Long URLs can conceal the actual destination.")
    if len(url)>200: flag(8,"Extremely long URL","The URL is unusually long.")
    if "@" in p.netloc: flag(20,"Misleading URL syntax","An @ symbol may obscure the real hostname.")
    if host.startswith("xn--") or ".xn--" in host: flag(18,"Punycode domain","Internationalized domain encoding may be used in lookalike domains.")
    try:
        ipaddress.ip_address(host); flag(25,"IP-based hostname","The website uses an IP address instead of a normal domain.")
    except ValueError: pass
    if host in SHORTENERS: flag(15,"URL shortener","The destination is hidden behind a shortening service.")
    labels=host.split(".")
    if len(labels)>4: flag(10,"Many subdomains","The hostname contains an unusually large number of labels.")
    if "-" in host: flag(5,"Hyphenated hostname","Hyphens can appear in deceptive lookalike domains.")
    if any(c.isdigit() for c in host): flag(5,"Digits in hostname","Check whether digits imitate letters in a brand name.")
    words=set(re.findall(r"[a-zA-Z]+",url.lower()))
    matched=sorted(words & SUSPICIOUS_WORDS)
    if matched: flag(min(18,4*len(matched)),"Sensitive keywords","Found: "+", ".join(matched))
    if p.port and p.port not in (80,443): flag(10,"Unusual port","The URL uses a non-standard web port.")
    if p.query and len(p.query)>120: flag(5,"Long query string","The query contains a large amount of data.")
    if host.count(".")>=3: flag(4,"Multiple hostname levels","Review the registered domain carefully.")

    safety, safety_note=safe_public_host(host)
    live={"checked":False,"status":"Skipped","final_url":None,"certificate":None,"notes":[]}
    if not safety:
        live["notes"].append(safety_note)
    else:
        if safety_note: live["notes"].append(safety_note)
        if p.scheme=="https": live["certificate"]=inspect_certificate(host,p.port or 443)
        # Fetch only public destinations; redirect targets are revalidated at every hop.
        current=url
        headers={"User-Agent":"SafePhishingAnalysisDemo/1.0 (educational security project)"}
        try:
            for hop in range(MAX_REDIRECTS+1):
                cp=urlparse(current)
                ok,note=safe_public_host(cp.hostname or "")
                if not ok: raise RuntimeError(note)
                response=requests.get(current,headers=headers,timeout=TIMEOUT,allow_redirects=False,stream=True)
                status=response.status_code
                location=response.headers.get("Location")
                response.close()
                if status in (301,302,303,307,308) and location:
                    if hop==MAX_REDIRECTS: live["notes"].append("Redirect limit reached."); break
                    current=urljoin(current,location)
                    continue
                live.update({"checked":True,"status":str(status),"final_url":current})
                if status>=400: flag(8,"Website returned an error","HTTP status: "+str(status))
                break
        except Exception as e:
            live["notes"].append("Live request could not be completed: "+str(e)[:180])

    score=max(0,min(100,score))
    level="Low"
    if score>=60: level="Critical"
    elif score>=40: level="High"
    elif score>=20: level="Medium"
    return {"url":url,"host":host,"score":score,"level":level,"findings":findings,"live":live,
            "scanned_at":datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}

@app.route("/",methods=["GET","POST"])
def index():
    result=None; error=None
    if request.method=="POST":
        target=request.form.get("url","")
        try:
            result=analyze(target)
            con=db()
            con.execute("INSERT INTO scans(url,score,level,findings,scanned_at) VALUES(?,?,?,?,?)",
                (result["url"],result["score"],result["level"],json.dumps(result["findings"]),result["scanned_at"]))
            con.commit(); con.close()
        except ValueError as e: error=str(e)
        except Exception as e: error="Analysis failed safely: "+str(e)[:200]
    con=db(); history=con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall(); con.close()
    return render_template("index.html",result=result,error=error,history=history)

@app.route("/awareness")
def awareness():
    return render_template("awareness_center.html")

@app.route("/awareness/batches")
def awareness_batches():
    return render_template("awareness_batches.html")

@app.route("/phishing-awareness")
def phishing_awareness():
    return render_template("awareness.html")


LESSON_CONTENT = [{'title': 'Email & phishing', 'subtitle': 'Read the message, not just the logo.', 'sections': [('How phishing works', 'Phishing is a deceptive message designed to make a recipient reveal information, open a harmful attachment, approve an action, or visit a fraudulent page. It may arrive through email, a chat platform, a collaboration tool, or a social network. Modern phishing can be grammatically perfect and can imitate familiar branding; spelling mistakes are only one possible clue.'), ('Common warning signals', 'Look for an unexpected request, pressure to act quickly, a threat of account closure, an unusual attachment, a request for passwords or one-time codes, or a link whose destination does not match the claimed organization. A familiar display name is not proof of identity. Inspect the actual sender address and the destination domain.'), ('Case file: the account warning', "A message says: “Your campus mailbox will be disabled in 15 minutes. Sign in now to retain access.” The deadline is designed to reduce careful thinking. The safe response is to avoid the embedded link, open the institution's known portal independently, and contact IT through a directory or previously verified channel. Do not reply with credentials."), ('Attachments and QR codes', 'Unexpected files can exploit software weaknesses or persuade a person to enable macros, run scripts, or install an application. QR codes can hide the destination just as shortened links can. Preview or inspect the destination using a trusted method, and never bypass browser or endpoint warnings merely because the message looks official.'), ('What to do', "Pause; verify the sender and request through an independent channel; report the message using your organization's process; and delete or quarantine it only after reporting when required. If you already clicked or submitted information, disconnect from suspicious activity where appropriate, change exposed credentials from a trusted device, revoke sessions, and contact support promptly.")], 'quiz': [('A message threatens immediate account closure and asks you to sign in through its link. What is the safest first step?', ['Use the link quickly', 'Open the known official portal independently', 'Reply asking if it is real'], 1), ("Which detail is strongest evidence to investigate a message's identity?", ['The logo looks familiar', "The sender's display name", 'The full sender address and independently verified request'], 2)]}, {'title': 'Safe browsing & deceptive domains', 'subtitle': 'A trustworthy-looking address can still mislead.', 'sections': [('The hostname matters', 'A URL may contain a scheme, hostname, path, query, and fragment. In https://login.example.test/account, the hostname is login.example.test. In a deceptive URL, text before an @ symbol may be user information rather than the destination host. Read the actual hostname from right to left and identify the registrable domain carefully.'), ('Case file: a Unicode lookalike', 'Compare the sample labels `hello.test` and `hellо.test`. In the second label, the character that appears to be “o” is Cyrillic small letter о (U+043E), not Latin small letter o (U+006F). The letters can look nearly identical in many fonts, but the strings are different. This is called a homograph or homoglyph-style domain deception. These examples use the reserved `.test` suffix and are educational, not live destinations.'), ('Internationalized domains and Punycode', 'Domain names can contain Unicode characters. Browsers and domain systems may represent internationalized labels using ASCII-compatible Punycode, often beginning with `xn--`. This encoding is not automatically malicious—many legitimate international domains use it—but it is a reason to examine a suspicious lookalike carefully. A visual comparison alone is not reliable.'), ('Other domain tricks', 'Attackers may use extra subdomains, misspellings, inserted hyphens, character substitutions such as 0 for o or l for 1, URL shorteners, misleading paths, or a hostname that includes a trusted name only as a subdomain. `trusted-brand.attacker.test` is controlled by the domain at the right-hand end, not by the brand-like text at the left.'), ('Verification routine', "Do not rely only on the padlock or HTTPS: encryption protects the connection, not the honesty of the site. Use bookmarks or type a known address; inspect the browser's actual hostname; compare character-by-character when a domain is unexpected; use a reputable security tool or organizational IT process; and never enter credentials until the destination is verified.")], 'quiz': [('In the sample `hellо.test`, the apparent “o” is Cyrillic U+043E. What does this demonstrate?', ['A different Unicode character can imitate a Latin character', 'HTTPS automatically converts it to a safe domain', 'The two domain strings are identical'], 0), ('What does HTTPS establish by itself?', ['That the website is approved by your college', 'That the connection is encrypted to the site presented', 'That the page cannot be a phishing page'], 1)]}, {'title': 'Passwords & identity', 'subtitle': 'Protect the account—and the recovery path.', 'sections': [('Credential reuse', 'A password reused across services creates a chain reaction: if one service leaks it, attackers may try the same combination elsewhere. Use unique passwords for important accounts and a reputable password manager to generate and store them.'), ('Multi-factor authentication', 'MFA adds a second proof beyond a password. Authenticator apps, security keys, and passkeys can offer stronger protection than codes delivered by SMS in many threat models. MFA is not a reason to approve unexpected prompts: repeated approval requests may be MFA fatigue or push bombing.'), ('OTP and recovery scams', 'A one-time password, recovery code, or login approval is effectively a temporary key. Support staff should not ask you to read an OTP to them. Never share recovery codes in chat or email. If a prompt appears when you are not signing in, deny it and investigate.'), ('Case file: the helpful caller', 'A caller claims to be technical support and says an account is under attack. They ask you to share an OTP to stop the attack. The urgency and authority are a pretext. End the call and contact the official support number or portal independently.'), ('Account recovery', 'Keep recovery email and phone details current, store backup codes securely, review active sessions and connected apps, and turn on login alerts where available. If credentials are exposed, change them from a trusted device, terminate unknown sessions, and report the incident.')], 'quiz': [('A login approval appears when you are not signing in. What should you do?', ['Approve it to stop repeated alerts', 'Deny it and investigate through official support', 'Send the approval code to the helpdesk caller'], 1), ('Why should passwords be unique across services?', ['It makes them easier to memorize', 'A leak on one service cannot directly unlock reused credentials elsewhere', 'Unique passwords prevent every phishing attempt'], 1)]}, {'title': 'Device security', 'subtitle': 'Reduce the opportunities attackers can use.', 'sections': [('Updates and patching', 'Updates repair known software weaknesses and improve security controls. Install operating-system, browser, and application updates through official settings or trusted vendor channels. A message or pop-up asking you to install an unknown “urgent patch” may itself be malicious.'), ('Downloads and software', 'Download applications from official stores or vendor websites. Check the publisher and requested permissions. Avoid pirated installers, unknown browser extensions, and files sent unexpectedly. Do not disable antivirus or endpoint protection just because an installer requests it.'), ('Public and shared devices', 'Avoid entering sensitive credentials on public computers. Sign out fully, do not save passwords, and use a trusted device for banking or account recovery. On shared systems, treat files and browser sessions as potentially accessible to others.'), ('Case file: the USB giveaway', 'A found USB drive labeled “salary list” or “exam results” uses curiosity to prompt plugging it in. Do not connect unknown media to a personal or organizational device. Give it to the responsible IT/security team.'), ('Backups and response', "Keep important data backed up according to your organization's policy, ideally with a copy protected from ordinary device access. If a device behaves suspiciously, stop using it for sensitive accounts and contact support; preserve relevant details rather than deleting evidence impulsively.")], 'quiz': [('You find an unknown USB drive labeled with an interesting file name. What is the safe response?', ['Plug it in but do not open files', 'Give it to IT/security without connecting it', 'Connect it to a shared computer'], 1), ('Where should you obtain a security update?', ['A random pop-up download', 'An official vendor or device update channel', 'A file-sharing link from an unknown sender'], 1)]}, {'title': 'Data & privacy', 'subtitle': 'Share deliberately, with the right person.', 'sections': [('Data minimization', 'Personal, academic, and workplace information can be used for impersonation, account recovery, fraud, or targeted social engineering. Share only the information necessary for the task and only with an authorized recipient.'), ('Sensitive information', 'Passwords, OTPs, recovery codes, payment details, identity documents, private student records, and confidential business information require special care. A request that is unusual, urgent, or outside normal policy should be verified before disclosure.'), ('Oversharing and public profiles', 'Public posts can reveal names, schedules, locations, relationships, projects, and organizational details. Attackers may combine small facts into a convincing pretext. Review privacy settings and think about what a stranger could infer from a post.'), ('Case file: fake event registration', 'A message offers a prize but asks for a student ID, date of birth, and payment information through an unfamiliar form. Confirm the event and organizer through an official channel; do not provide unnecessary data to claim an unexpected reward'), ('Safe sharing', 'Check the recipient, purpose, and channel. Use approved file-sharing tools, limit access, avoid public links for private documents, and remove access when it is no longer needed. Report accidental disclosure promptly')], 'quiz': [('A form asks for more personal information than is needed to register for an event. What should you do?', ['Submit everything to avoid losing the offer', 'Verify the organizer and question why each field is needed', "Use another person's details"], 1), ('What is data minimization?', ['Collecting or sharing only the information needed for a legitimate purpose', 'Making every file publicly accessible', 'Keeping all personal information forever'], 0)]}, {'title': 'Report & recover', 'subtitle': 'A quick, calm response limits harm.', 'sections': [('Report early', "Report suspicious messages, calls, websites, or account activity using the organization's designated security channel. Early reporting can help protect others and support investigation. Include the time, sender, URL, screenshots, and what action you took when safe and appropriate"), ('If you clicked', "A click does not always mean compromise, but act promptly. Close the page; do not enter more information; run the organization's approved security checks; and contact IT if a download occurred, a warning appeared, or the device behaves unexpectedly"), ('If credentials were entered', 'From a trusted device, change the affected password and any reused passwords, revoke active sessions, check recovery settings, and enable or reset MFA. Contact the service or institution through official channels. If financial information was shared, contact the bank or provider promptly'), ('Preserve evidence', 'Keep the original message or report it as an attachment where your organization requests. Save relevant timestamps and screenshots. Avoid forwarding suspicious links widely or publicly posting sensitive evidence'), ('Case file: suspected compromise', 'You entered a password on a page later identified as suspicious. Do not wait for proof of misuse. Change the password from a clean device, revoke sessions, notify support, monitor account activity, and follow incident-response instructions')], 'quiz': [('You entered your password on a suspicious page. What should happen next?', ['Wait until money or data disappears', 'Change it from a trusted device, revoke sessions, and report it', 'Only clear browser history'], 1), ('Why report a suspicious message even if you did not click it?', ['It may help protect other recipients and support investigation', "Reporting automatically proves the sender's identity", 'It is only useful after a confirmed breach'], 0)]}]

@app.route("/awareness/lesson/<int:lesson_id>")
@app.route("/phishing-awareness/lesson/<int:lesson_id>")
def awareness_lesson(lesson_id):
    if lesson_id < 1 or lesson_id > len(LESSON_CONTENT):
        return "Lesson not found", 404
    lesson = LESSON_CONTENT[lesson_id - 1]
    return render_template("lesson_detail.html", lesson=lesson, lesson_id=lesson_id,
                           lesson_count=len(LESSON_CONTENT))

SOCIAL_LESSONS = [
    {"title":"Phishing & Email Manipulation", "subtitle":"Recognize how attackers use messages to influence decisions.", "batches":[
      ("Batch 1 · Anatomy of a phishing message", ["Phishing messages imitate trusted people or services to prompt a risky action. Inspect the full sender address, unexpected requests, attachments, and the destination behind each link.", "Urgency, threats, rewards, and authority are common pressure tactics. Slow down and verify through a known channel instead of replying to the message."], "Practice: a message says your account will close in ten minutes. Open the official portal independently; do not use its embedded sign-in link."),
      ("Batch 2 · Attachments, QR codes & reply traps", ["Unexpected documents may ask you to enable macros, run scripts, or install software. QR codes and shortened links can conceal destinations.", "Report suspicious messages using your institution or organization's process. If you interacted with one, preserve relevant details and contact support promptly."], "Remember: a polished logo or correct grammar does not authenticate a message.")], "quiz":[("Which is the safest way to verify an unexpected account warning?",["Use the message link immediately","Open the known official portal separately","Reply with account details"],1),("What should you do with an unexpected attachment asking you to enable content?",["Enable it to view the document","Forward it to friends","Do not enable it; verify and report"],2)]},
    {"title":"Pretexting & Impersonation", "subtitle":"Understand invented stories and false authority.", "batches":[
      ("Batch 1 · Building a believable pretext", ["Pretexting is a fabricated scenario used to make a request seem legitimate. An attacker may pose as IT support, a courier, a classmate, a manager, or a service provider.", "The story may include personal details gathered from public posts. A familiar name or accurate detail is not proof that the person is genuine."], "Verify identity and the request separately, using a directory, known number, or face-to-face confirmation."),
      ("Batch 2 · Authority, trust & unusual requests", ["Attackers may claim seniority, create an emergency, or ask you to bypass normal procedures. Requests for secrecy, credentials, gift cards, or unusual access deserve scrutiny.", "Follow approved processes even when a request appears to come from someone important. Escalate politely when verification is unavailable."], "A legitimate request should tolerate a reasonable verification step.")], "quiz":[("A caller claims to be your administrator and asks you to skip verification. What should you do?",["Comply because they sound senior","Verify using a known official channel","Share only part of your password"],1),("What is a pretext?",["A fabricated story used to make a request seem credible","A secure password manager","A software update"],0)]},
    {"title":"Vishing, Smishing & OTP Scams", "subtitle":"Identify manipulation over calls and text messages.", "batches":[
      ("Batch 1 · Vishing and fake support calls", ["Vishing uses voice calls to pressure someone into revealing information or taking action. Caller ID can be spoofed, so the displayed number is not reliable proof.", "Never disclose passwords, recovery codes, or one-time passwords to a caller. End an unexpected call and contact the organization through its official support channel."], "If a caller says an OTP is needed to protect you, treat the request as a warning sign."),
      ("Batch 2 · Smishing and delivery lures", ["Smishing uses SMS or messaging apps. Fake parcel fees, account alerts, prizes, and payment notices can lead to credential or payment theft.", "Avoid unfamiliar short links. Check parcel or account information in the official app or website that you open yourself."], "Do not let a small fee or urgent delivery deadline bypass your checks.")], "quiz":[("A caller asks you to read an OTP to stop an attack. What is safest?",["Read it to them","Keep it private and verify support independently","Send it in a text"],1),("How should you check an unexpected parcel message?",["Use the carrier's official app or website","Pay through its shortened link","Reply with your card details"],0)]},
    {"title":"Business Email & Payment Fraud", "subtitle":"Protect approvals, invoices, and sensitive business workflows.", "batches":[
      ("Batch 1 · Business email compromise", ["Business email compromise (BEC) often impersonates an executive, supplier, or colleague to request money, confidential files, or account changes.", "Messages may look like ordinary business correspondence and may not contain a suspicious attachment. Focus on unusual requests, changed details, secrecy, and urgency."], "Verify high-impact requests with a callback to a previously known number—not the number included in the new email."),
      ("Batch 2 · Invoice and bank-detail changes", ["Fraudsters may send altered invoices or claim that a supplier's bank account has changed. A single email should not override payment controls.", "Use documented dual approval, trusted vendor records, and independent verification. Report suspected fraud quickly to finance and security teams."], "Never treat an email-only change to payment details as sufficient authorization.")], "quiz":[("A supplier emails new bank details. What is the best control?",["Update them immediately","Independently call the supplier using a known number","Reply asking for confirmation"],1),("Why are approval procedures important?",["They slow all work unnecessarily","They provide independent checks against manipulation","They make email automatically secure"],1)]},
    {"title":"Baiting, Tailgating & Physical Social Engineering", "subtitle":"Recognize attacks that exploit curiosity or physical access.", "batches":[
      ("Batch 1 · Baiting and unknown devices", ["Baiting uses curiosity or a promised reward, such as a USB labeled with exam results or confidential files. Connecting unknown media can expose a device to malware.", "Do not plug in found storage or scan unknown QR codes. Give suspicious items to authorized IT or security staff."], "The safest response to an unknown USB is to leave it disconnected and report it."),
      ("Batch 2 · Tailgating and access requests", ["Tailgating occurs when an unauthorized person follows an authorized person into a restricted area. The attacker may carry items or claim they forgot a badge.", "Do not hold secure doors for unknown individuals or lend badges. Follow visitor procedures and contact security when someone needs help."], "Courtesy should not override access-control policy.")], "quiz":[("You find a USB labeled 'important results'. What should you do?",["Connect it to identify the owner","Leave it disconnected and report it","Try it on a spare computer"],1),("Someone without a badge asks you to hold a secure door. What is safest?",["Let them follow you","Follow access policy and direct them to reception/security","Lend your badge"],1)]}
]

@app.route("/social-awareness")
def social_awareness():
    return render_template("social_awareness.html", lessons=SOCIAL_LESSONS)

@app.route("/social-awareness/lesson/<int:lesson_id>")
def social_lesson(lesson_id):
    if lesson_id < 1 or lesson_id > len(SOCIAL_LESSONS):
        return "Lesson not found", 404
    return render_template("social_lesson.html", lesson=SOCIAL_LESSONS[lesson_id-1], lesson_id=lesson_id,
                           lesson_count=len(SOCIAL_LESSONS), course_type="social")

@app.route("/history")
def history():
    con=db(); rows=con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall(); con.close()
    return render_template("history.html",history=rows)

@app.route("/api/stats")
def api_stats():
    con=db()
    rows=con.execute("SELECT score,level,findings,scanned_at FROM scans ORDER BY id DESC LIMIT 500").fetchall()
    con.close()
    levels={"Low":0,"Medium":0,"High":0,"Critical":0}
    categories={}
    days={}
    for row in rows:
        levels[row["level"]]=levels.get(row["level"],0)+1
        day=(row["scanned_at"] or "")[:10]
        if day: days[day]=days.get(day,0)+1
        try:
            for finding in json.loads(row["findings"] or "[]"):
                name=finding.get("title","Other")
                categories[name]=categories.get(name,0)+1
        except (ValueError,TypeError): pass
    day_keys=sorted(days)[-7:]
    return jsonify({"total":len(rows),"levels":levels,"days":{"labels":day_keys,"values":[days[d] for d in day_keys]},
        "categories":{"labels":list(sorted(categories,key=categories.get,reverse=True)[:8]),
        "values":[categories[k] for k in sorted(categories,key=categories.get,reverse=True)[:8]]},
        "average":round(sum(r["score"] or 0 for r in rows)/len(rows)) if rows else 0,
        "high_risk":levels["High"]+levels["Critical"]})

if __name__=="__main__":
    app.run(debug=False,host="127.0.0.1",port=5000)
