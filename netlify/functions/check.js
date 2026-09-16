exports.handler = async function (event) {
  // Handle CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
      },
    };
  }

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  // Parse request
  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid request body" }),
    };
  }

  const url = (body.url || "").trim();
  if (!url) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "No URL provided" }),
    };
  }

  // Parse and validate URL
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return {
      statusCode: 400,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ error: "Invalid URL format" }),
    };
  }

  // ---- Run all checks ----
  const findings = [];
  let threatLevel = "safe"; // safe | suspicious | dangerous

  function addFinding(check, result, severity) {
    findings.push({ check, result, severity });
    if (severity === "dangerous") threatLevel = "dangerous";
    else if (severity === "suspicious" && threatLevel === "safe")
      threatLevel = "suspicious";
  }

  // 1. URLhaus exact-URL lookup (abuse.ch — free, no key)
  try {
    const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "url=" + encodeURIComponent(url),
    });
    const data = await res.json();

    if (data.query_status === "listed") {
      addFinding(
        "Malware database (URLhaus)",
        "This exact URL is listed in the URLhaus malware database." +
          (data.threat ? " Threat type: " + data.threat + "." : "") +
          (data.date_added
            ? " First reported: " + data.date_added + "."
            : ""),
        "dangerous"
      );
    } else {
      addFinding(
        "Malware database (URLhaus)",
        "This URL is not listed in the URLhaus malware database.",
        "safe"
      );
    }
  } catch {
    addFinding(
      "Malware database (URLhaus)",
      "Could not reach the URLhaus database right now. This check was skipped.",
      "unknown"
    );
  }

  // 2. Protocol check
  if (parsed.protocol === "http:") {
    addFinding(
      "Connection security",
      'This link uses plain HTTP, not HTTPS. The connection is not encrypted, so data you send to this site (passwords, card numbers) could be intercepted by anyone on the same network.',
      "suspicious"
    );
  } else if (parsed.protocol === "https:") {
    addFinding(
      "Connection security",
      "This link uses HTTPS. The connection between you and the site is encrypted.",
      "safe"
    );
  } else if (
    ["javascript:", "data:", "vbscript:", "blob:"].includes(parsed.protocol)
  ) {
    addFinding(
      "Connection security",
      'This is not a normal web link. It uses the "' +
        parsed.protocol +
        '" protocol, which can run code on your device. Do not open it.',
      "dangerous"
    );
  }

  // 3. IP address instead of domain name
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4.test(parsed.hostname)) {
    addFinding(
      "Domain type",
      "This link points to a raw IP address (" +
        parsed.hostname +
        ") instead of a named website. Legitimate sites almost always use a domain name like example.com. IP-based links are commonly used in phishing and malware attacks.",
      "suspicious"
    );
  }

  // 4. Suspicious TLD
  const suspiciousTlds = [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".top", ".xyz", ".club", ".work",
    ".date", ".racing", ".win", ".bid", ".stream",
    ".download", ".loan", ".men", ".click", ".link",
    ".surf", ".rest", ".cam", ".icu", ".monster",
  ];
  const tld = "." + parsed.hostname.split(".").pop().toLowerCase();
  if (suspiciousTlds.includes(tld)) {
    addFinding(
      "Domain extension",
      'This link uses the "' +
        tld +
        '" domain extension, which is frequently associated with spam, phishing, and throwaway scam sites. Not every "' +
        tld +
        '" site is malicious, but extra caution is warranted.',
      "suspicious"
    );
  }

  // 5. URL shortener
  const shorteners = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "lnkd.in",
    "shorte.st", "clck.ru", "tiny.cc", "rb.gy", "cutt.ly",
    "shorturl.at", "v.gd", "qr.ae", "t.ly", "surl.li",
  ];
  if (shorteners.includes(parsed.hostname.toLowerCase())) {
    addFinding(
      "URL shortener detected",
      'This is a shortened link from "' +
        parsed.hostname +
        '". The real destination is hidden behind the shortener. Shortened links can redirect you anywhere, including dangerous sites. We cannot verify where it actually leads without following it.',
      "suspicious"
    );
  }

  // 6. @ symbol in URL (credential-based redirect trick)
  if (url.includes("@") && !url.startsWith("mailto:")) {
    addFinding(
      "URL structure",
      'This URL contains an "@" symbol. This is a well-known trick used to disguise the real destination of a link. Everything before the "@" is ignored by the browser, so the domain you see may not be where you actually end up.',
      "dangerous"
    );
  }

  // 7. Excessive subdomains
  const parts = parsed.hostname.split(".");
  if (parts.length > 4) {
    addFinding(
      "Subdomain depth",
      "This URL has " +
        (parts.length - 2) +
        " levels of subdomains (" +
        parsed.hostname +
        "). An unusually deep subdomain structure is a common trick to make a phishing URL look like a legitimate website.",
      "suspicious"
    );
  }

  // 8. Phishing keywords in URL
  const phishingKeywords = [
    "login", "verify", "account", "update", "secure",
    "banking", "confirm", "password", "credential", "signin",
    "sign-in", "log-in", "security-check", "account-verify",
    "wallet", "recover", "suspend", "locked", "unauthorized",
    "billing", "payment", "invoice", "paypal", "appleid",
  ];
  const urlLower = url.toLowerCase();
  const matched = phishingKeywords.filter(function (kw) {
    return urlLower.includes(kw);
  });
  if (matched.length >= 2) {
    addFinding(
      "Phishing indicators",
      "This URL contains multiple keywords commonly found in phishing links: " +
        matched.map(function (w) { return '"' + w + '"'; }).join(", ") +
        ". These words are frequently used to trick people into entering personal information on fake sites.",
      "suspicious"
    );
  }

  // 9. Dangerous file extension
  const dangerousExts = [
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".dll",
    ".vbs", ".wsf", ".ps1", ".jar", ".apk", ".dmg",
    ".iso", ".img", ".hta", ".cpl", ".pif",
  ];
  const pathLower = parsed.pathname.toLowerCase();
  var foundExt = null;
  for (var i = 0; i < dangerousExts.length; i++) {
    if (pathLower.endsWith(dangerousExts[i])) {
      foundExt = dangerousExts[i];
      break;
    }
  }
  if (foundExt) {
    addFinding(
      "File download risk",
      'This link appears to download a file with the "' +
        foundExt +
        '" extension. This type of file can run programs on your device and may contain malware or viruses. Do not download it unless you completely trust the source.',
      "dangerous"
    );
  }

  // 10. Very long URL
  if (url.length > 250) {
    addFinding(
      "URL length",
      "This URL is unusually long (" +
        url.length +
        " characters). Extremely long URLs are sometimes used to hide suspicious content, encode tracking data, or bypass security filters.",
      "suspicious"
    );
  }

  // 11. Heavy URL encoding
  const encodedParts = url.match(/%[0-9A-Fa-f]{2}/g);
  const encodedCount = encodedParts ? encodedParts.length : 0;
  if (encodedCount > 5) {
    addFinding(
      "URL encoding",
      "This URL contains " +
        encodedCount +
        " encoded characters. Heavy URL encoding is sometimes used to disguise the real destination or to bypass security filters.",
      "suspicious"
    );
  }

  // 12. Google Safe Browsing (optional — needs API key in env var)
  const safeBrowsingKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (safeBrowsingKey) {
    try {
      const sbRes = await fetch(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
          safeBrowsingKey,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client: {
              clientId: "isthislinksafe",
              clientVersion: "1.0.0",
            },
            threatInfo: {
              threatTypes: [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
              ],
              platformTypes: ["ANY_PLATFORM"],
              threatEntryTypes: ["URL"],
              threatEntries: [{ url: url }],
            },
          }),
        }
      );
      const sbData = await sbRes.json();

      if (sbData.matches && sbData.matches.length > 0) {
        const threats = sbData.matches
          .map(function (m) {
            return m.threatType.replace(/_/g, " ").toLowerCase();
          })
          .join(", ");
        addFinding(
          "Google Safe Browsing",
          "Google has flagged this URL as dangerous. Threat types found: " +
            threats +
            ". Google maintains one of the largest databases of dangerous websites in the world.",
          "dangerous"
        );
      } else {
        addFinding(
          "Google Safe Browsing",
          "Google Safe Browsing has not flagged this URL as dangerous.",
          "safe"
        );
      }
    } catch {
      addFinding(
        "Google Safe Browsing",
        "Could not reach Google Safe Browsing right now. This check was skipped.",
        "unknown"
      );
    }
  }

  // ---- Return results ----
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
    body: JSON.stringify({
      url: url,
      threatLevel: threatLevel,
      findings: findings,
      checkedAt: new Date().toISOString(),
    }),
  };
};
