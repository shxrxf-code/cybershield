"""Phishing lexicon and brand knowledge base.

All matching is performed against a whitespace-collapsed, NFKC-normalised and
lowercased form of the input (see :func:`app.detection_engine.text.normalise_text`),
and additionally against a fully de-spaced form, so that ``v e r i f y`` and
``verıfy``-style padding does not evade the rules.

Every entry is deliberately generic. The keyword list alone can never establish
maliciousness — these are *feature* signals that the risk engine combines with
independent evidence such as domain age, TLS state and reputation.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Generic phishing vocabulary
# ---------------------------------------------------------------------------
# Weight reflects how strongly the term correlates with credential phishing in
# published phishing-kit corpora. Kept low because the words are common on the
# legitimate web ("account settings", "password reset" on a real bank).
KEYWORD_WEIGHTS: dict[str, float] = {
    # Credential / authentication
    "login": 0.55,
    "log-in": 0.55,
    "signin": 0.55,
    "sign-in": 0.55,
    "logon": 0.45,
    "verify": 0.60,
    "verification": 0.55,
    "authenticate": 0.60,
    "authorization": 0.45,
    "credential": 0.65,
    "password": 0.60,
    "passwd": 0.60,
    "username": 0.40,
    "otp": 0.55,
    "2fa": 0.50,
    "mfa": 0.50,
    "one-time": 0.50,
    "recovery": 0.40,
    "recover": 0.35,
    "unlock": 0.45,
    "suspended": 0.60,
    "suspend": 0.55,
    # Account / payment
    "account": 0.35,
    "wallet": 0.65,
    "payment": 0.45,
    "billing": 0.40,
    "invoice": 0.35,
    "refund": 0.45,
    "banking": 0.55,
    "bank": 0.40,
    "crypto": 0.45,
    "bitcoin": 0.45,
    "seed-phrase": 0.75,
    "security-phrase": 0.75,
    # Urgency / pressure
    "urgent": 0.55,
    "immediately": 0.40,
    "expire": 0.45,
    "expiring": 0.50,
    "expired": 0.35,
    "suspend": 0.55,
    "final-notice": 0.70,
    "last-chance": 0.65,
    "act-now": 0.65,
    "limited-time": 0.60,
    "24-hours": 0.50,
    "deadline": 0.40,
    # Update / security pretext
    "update": 0.30,
    "confirm": 0.45,
    "validate": 0.45,
    "secure": 0.30,
    "security-alert": 0.70,
    "security-alert": 0.70,
    "alert": 0.25,
    "warning": 0.20,
    "notice": 0.20,
    "mandatory": 0.45,
    "required-action": 0.65,
    "click-here": 0.55,
    "download": 0.25,
    "install": 0.25,
    "support": 0.15,
    "help-desk": 0.45,
    "customer-service": 0.30,
}

#: Compiled alternation for fast whole-text matching.
KEYWORD_RE = re.compile("|".join(re.escape(k) for k in sorted(KEYWORD_WEIGHTS, key=len, reverse=True)))

# ---------------------------------------------------------------------------
# Urgency / social-engineering phrases
# ---------------------------------------------------------------------------
URGENCY_PHRASES: tuple[str, ...] = (
    "act now",
    "immediate action",
    "immediately",
    "within 24 hours",
    "within 48 hours",
    "right away",
    "final notice",
    "final warning",
    "last chance",
    "limited time",
    "time-sensitive",
    "expires today",
    "expires in",
    "expiring soon",
    "will be suspended",
    "will be closed",
    "will be terminated",
    "avoid termination",
    "your account will be",
    "failure to comply",
    "failure to respond",
    "unauthorized activity",
    "unusual activity",
    "suspicious activity",
    "security breach",
    "has been hacked",
    "has been compromised",
    "permanent closure",
    "seize the opportunity",
    "don't miss out",
    "do not miss",
    "urgent notice",
    "important notice",
    "attention required",
    "action required",
    "verify immediately",
)

# ---------------------------------------------------------------------------
# Credential solicitation
# ---------------------------------------------------------------------------
CREDENTIAL_REQUEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:enter|provide|re-?enter|supply|input|type)\s+(?:your\s+)?(?:password|passcode|pin|credentials?|login|username|user\s*name)\b", re.I),
    re.compile(r"\bconfirm\s+(?:your\s+)?(?:password|identity|credentials?|account\s+details?|billing)\b", re.I),
    re.compile(r"\b(?:sign|log)\s*in\s+(?:to|at|via)\s+(?:your|our|the)\b", re.I),
    re.compile(r"\b(?:restore|regain|reset)\s+(?:access|your\s+account)\b", re.I),
    re.compile(r"\byou\s+(?:will\s+be|are)\s+(?:redirected|logged\s+out|disconnected)\b", re.I),
    re.compile(r"\bsession\s+(?:has\s+)?(?:expired|timed\s*out)\b", re.I),
    re.compile(r"\b(?:verify|validate|confirm)\s+(?:your\s+)?identity\b", re.I),
    re.compile(r"\bavoid\s+(?:permanent\s+)?(?:account\s+)?(?:deletion|closure|suspension)\b", re.I),
    re.compile(r"\bkeep\s+(?:your\s+)?(?:account|access)\s+(?:active|open)\b", re.I),
    re.compile(r"\bseed\s*phrase|private\s+key|recovery\s+phrase|2\s*fa\s*code|one[-\s]?time\s+(?:password|code)\b", re.I),
)

# ---------------------------------------------------------------------------
# Financial solicitation
# ---------------------------------------------------------------------------
FINANCIAL_REQUEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:wire|transfer|send)\s+(?:the\s+)?(?:funds?|money|payment|balance)\b", re.I),
    re.compile(r"\b(?:bank|account)\s+details?\b", re.I),
    re.compile(r"\b(?:credit|debit)\s+card\s+(?:number|details?|info)\b", re.I),
    re.compile(r"\bcvv2?\b|\bcvc\b|\bsecurity\s+code\b", re.I),
    re.compile(r"\b(?:sort\s+code|routing\s+number|iban|swift\s*code|bic\s*code)\b", re.I),
    re.compile(r"\bpay(?:ment|now)\s+(?:fee|charge|invoice|amount)\b", re.I),
    re.compile(r"\brefund\s+of\s+\$?\d", re.I),
    re.compile(r"\b(?:bitcoin|btc|eth|ethereum|monero|xmr|usdt)\s*(?:wallet|address)\b", re.I),
    re.compile(r"\bgift\s+card|google\s+play\s+card|itunes\s+card\b", re.I),
    re.compile(r"\b(?:invoice|payment)\s+(?:attached|enclosed|below)\b", re.I),
)

#: High-value targets where impersonation has severe consequences.
SENSITIVE_SECTORS: frozenset[str] = frozenset(
    {
        "banking", "financial", "government", "healthcare", "telecom",
        "utilities", "education", "technology", "cryptocurrency", "insurance",
    }
)

# ---------------------------------------------------------------------------
# Brand impersonation knowledge base
# ---------------------------------------------------------------------------
#: brand token -> official registrable domain. A brand token appearing in the
#: host or path while the registrable domain is *not* the official one is a
#: strong impersonation signal (e.g. ``paypal-secure.tk``).
BRAND_OFFICIAL_DOMAINS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal.me", "paypalobjects.com"}),
    "apple": frozenset({"apple.com", "icloud.com", "apple.news"}),
    "icloud": frozenset({"icloud.com", "apple.com"}),
    "microsoft": frozenset({"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "msn.com", "microsoftonline.com", "sharepoint.com"}),
    "outlook": frozenset({"outlook.com", "microsoft.com", "live.com", "office.com"}),
    "office365": frozenset({"office.com", "office365.com", "microsoft.com", "live.com"}),
    "office": frozenset({"office.com", "office365.com", "microsoft.com"}),
    "google": frozenset({"google.com", "gmail.com", "googlemail.com", "googleapis.com", "goo.gl", "youtube.com"}),
    "gmail": frozenset({"gmail.com", "google.com", "googlemail.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "aws.amazon.com", "amazonaws.com"}),
    "netflix": frozenset({"netflix.com", "nflxext.com"}),
    "facebook": frozenset({"facebook.com", "fb.com", "fbcdn.net", "messenger.com", "meta.com"}),
    "meta": frozenset({"meta.com", "facebook.com", "fb.com"}),
    "whatsapp": frozenset({"whatsapp.com", "wa.me"}),
    "instagram": frozenset({"instagram.com", "cdninstagram.com"}),
    "linkedin": frozenset({"linkedin.com", "lnkd.in"}),
    "twitter": frozenset({"twitter.com", "x.com", "t.co", "twimg.com"}),
    "telegram": frozenset({"telegram.org", "t.me", "telegram.me"}),
    "dropbox": frozenset({"dropbox.com", "dropboxusercontent.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "adobe": frozenset({"adobe.com", "acrobat.com"}),
    "github": frozenset({"github.com", "githubusercontent.com"}),
    "chase": frozenset({"chase.com", "jpmorganchase.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "bankofamerica": frozenset({"bankofamerica.com", "bofa.com"}),
    "citibank": frozenset({"citibank.com", "citi.com"}),
    "hsbc": frozenset({"hsbc.com", "hsbc.co.uk"}),
    "barclays": frozenset({"barclays.co.uk", "barclays.com"}),
    "santander": frozenset({"santander.co.uk", "santander.com", "santanderbank.com"}),
    "natwest": frozenset({"natwest.com"}),
    "lloyds": frozenset({"lloydsbank.com"}),
    "monzo": frozenset({"monzo.com"}),
    "revolut": frozenset({"revolut.com"}),
    "wise": frozenset({"wise.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "binance": frozenset({"binance.com", "binance.us"}),
    "kraken": frozenset({"kraken.com"}),
    "blockchain": frozenset({"blockchain.com"}),
    "steam": frozenset({"steampowered.com", "steamcommunity.com", "valvesoftware.com"}),
    "epicgames": frozenset({"epicgames.com"}),
    "roblox": frozenset({"roblox.com"}),
    "spotify": frozenset({"spotify.com"}),
    "uber": frozenset({"uber.com"}),
    "airbnb": frozenset({"airbnb.com"}),
    "walmart": frozenset({"walmart.com"}),
    "fedex": frozenset({"fedex.com"}),
    "ups": frozenset({"ups.com"}),
    "usps": frozenset({"usps.com", "usps.gov"}),
    "royalmail": frozenset({"royalmail.com"}),
    "dhl": frozenset({"dhl.com", "dhl.de"}),
    "irs": frozenset({"irs.gov"}),
    "hmrc": frozenset({"hmrc.gov.uk", "gov.uk"}),
    "nhs": frozenset({"nhs.uk", "gov.uk"}),
    "socialsecurity": frozenset({"ssa.gov"}),
    "medicare": frozenset({"medicare.gov"}),
    "dvla": frozenset({"gov.uk"}),
}

#: Flat token set for fast membership testing during impersonation checks.
BRAND_TOKENS: frozenset[str] = frozenset(BRAND_OFFICIAL_DOMAINS.keys())

# ---------------------------------------------------------------------------
# Typosquatting patterns
# ---------------------------------------------------------------------------
# Recognisable misspellings of high-value brands. Deliberately small and
# high-precision: a typo list that fires on ordinary domains creates noise.
TYPOSQUAT_VARIANTS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypai", "paypall", "paypa1", "paypai", "paypal-verify", "paypalsecure"}),
    "microsoft": frozenset({"microsft", "micros0ft", "microsoftonline-secure", "rnicrosoft", "micr0soft"}),
    "apple": frozenset({"applе", "appl3", "aaple", "apple-id", "appleid"}),
    "google": frozenset({"g00gle", "googie", "google-verify", "googIe"}),
    "amazon": frozenset({"amaz0n", "amazonn", "amason", "amazon-verify"}),
    "netflix": frozenset({"netfl1x", "netflix-verify", "netfIix"}),
    "facebook": frozenset({"faceboook", "fcebook", "facebook-secure", "faceb00k"}),
    "instagram": frozenset({"instagrarn", "instagram-verify", "1nstagram"}),
    "linkedin": frozenset({"linkedln", "linkedin-verify", "Iinkedin"}),
    "dropbox": frozenset({"dr0pbox", "dropb0x", "dropbox-secure"}),
    "docusign": frozenset({"docuslgn", "docusign-secure", "d0cusign"}),
    "chase": frozenset({"ch4se", "chase-secure", "chase-verify"}),
    "coinbase": frozenset({"coinb4se", "coinbase-secure"}),
    "binance": frozenset({"blnance", "binance-secure"}),
    "steam": frozenset({"stean", "steam-community", "steamcomminity"}),
    "whatsapp": frozenset({"whatsapp-verify", "whatsapp-secure", "what5app"}),
    "dhl": frozenset({"dh1", "dhl-express"}),
    "fedex": frozenset({"fedex-track", "fedeX"}),
}

# ---------------------------------------------------------------------------
# Secrecy and authority abuse (Business Email Compromise techniques)
# ---------------------------------------------------------------------------
# BEC succeeds through social pressure rather than technical evasion. These
# patterns capture the two strongest pressure levers: secrecy (suppress the
# victim's normal verification step) and borrowed authority (a named executive
# instructing the transfer).
SECRECY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:do\s*not|don't|never)\s+(?:tell|inform|notify|discuss|share|forward|alert)\b", re.I),
    re.compile(r"\b(?:keep|maintain)\s+(?:this\s+)?(?:confidential|secret|private|between\s+us)\b", re.I),
    re.compile(r"\b(?:strictly\s+)?(?:confidential|private\s+and\s+confidential)\b", re.I),
    re.compile(r"\bbefore\s+(?:speaking|talking|discussing)\s+with\b", re.I),
    re.compile(r"\b(?:no|without)\s+(?:questions|discussion|consultation)\b", re.I),
)

AUTHORITY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:dear\s+)?(?:mr|ms|mrs|dr|prof)\.?\s+[A-Z][a-z]+", re.I),
    re.compile(r"\b(?:as\s+(?:the\s+)?)?(?:ceo|cfo|cto|coo|president|director|chairman|chairwoman|partner|managing\s+director)\b", re.I),
    re.compile(r"\b(?:i\s+am|this\s+is)\s+(?:the\s+)?(?:ceo|cfo|cto|president|director)\b", re.I),
    re.compile(r"\bauthori[sz]ed\s+(?:by|personnel|representative|signatory)\b", re.I),
    re.compile(r"\b(?:on\s+behalf\s+of|at\s+the\s+request\s+of)\s+the\s+(?:ceo|cfo|board|management)\b", re.I),
)

# ---------------------------------------------------------------------------
# Link-text vs. destination mismatch
# ---------------------------------------------------------------------------
#: Anchor text that merely announces the destination, so a mismatch is meaningful.
GENERIC_LINK_TEXT: frozenset[str] = frozenset(
    {
        "click here", "here", "link", "this link", "download", "click",
        "open", "view", "continue", "update", "login", "log in", "sign in",
        "verify", "submit", "go", "read more", "more", "details", "info",
        "secure", "access", "confirm", "proceed", "next",
    }
)

#: Brand tokens are not interchangeable with a generic link label, so seeing a
#: brand in the anchor text while the href points elsewhere is a strong signal.
LINK_ANCHOR_RE = re.compile(
    r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S
)