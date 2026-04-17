export function analyzeURL(urlString) {
    if (!urlString || typeof urlString !== "string") return { score: 0, status: "Safe" };

    // Auto-prepend http if protocol is missing to parse correctly
    let url = urlString;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(url);
    } catch (e) {
        // Unparseable URL is extremely suspicious usually
        return { score: 100, status: "Danger" };
    }

    const unwwwhostname = parsedUrl.hostname.replace(/^www\./, "").toLowerCase();

    // 1. Direct IP Address Check (Highly suspicious)
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipv4Regex.test(unwwwhostname)) {
        return { score: 95, status: "Danger" };
    }

    // 2. Exact Root Domain Extraction
    const parts = unwwwhostname.split('.');
    let rootDomain = unwwwhostname;
    let tld = parts[parts.length - 1];

    if (parts.length > 2) {
        // Check for compound TLDs like .co.uk
        const compoundTlds = ['co.uk', 'co.in', 'com.au', 'ac.uk', 'org.uk', 'gov.in'];
        const possibleTld = parts[parts.length - 2] + '.' + parts[parts.length - 1];
        if (compoundTlds.includes(possibleTld)) {
            rootDomain = parts[parts.length - 3] + '.' + possibleTld;
            tld = possibleTld;
        } else {
            rootDomain = parts[parts.length - 2] + '.' + parts[parts.length - 1];
        }
    }

    const trustedDomains = [
        "google.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
        "linkedin.com", "youtube.com", "microsoft.com", "apple.com", "github.com",
        "paypal.com", "amazon.com", "netflix.com", "yahoo.com", "twitch.tv",
        "reddit.com", "wikipedia.org", "whatsapp.com", "spotify.com", "bing.com",
        "live.com", "office.com", "adobe.com", "zoom.us", "dropbox.com",
        "salesforce.com", "stripe.com", "tiktok.com", "chase.com", "bankofamerica.com",
        "wellsfargo.com", "citi.com", "capitalone.com", "americanexpress.com",
        "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
        "paytm.com", "phonepe.com", "flipkart.com", "meesho.com", "aliexpress.com",
        "outlook.com", "icloud.com", "stackoverflow.com", "vercel.com", "netlify.com",
        "atlassian.net", "duckduckgo.com"
    ];

    // 3. EXPLICIT ALLOWLIST: If the actual root domain is trusted, IT IS SAFE! (Score 0)
    if (trustedDomains.includes(rootDomain)) {
        return { score: 0, status: "Safe" };
    }

    // If we land here, the root domain is NOT natively trusted.
    // Time to accumulate risk score based on heuristics.
    let score = 0;

    // Penalty for untrusted domains sitting on plain HTTP
    if (parsedUrl.protocol === "http:") score += 15;

    // 4. Subdomain Impersonation (e.g., paypal.com.scamhacker.net)
    const subdomainPath = unwwwhostname.replace(`.${rootDomain}`, '');
    let impersonatingSubdomain = false;
    
    if (subdomainPath && subdomainPath !== unwwwhostname) {
        for (const brand of trustedDomains) {
            const brandRoot = brand.split('.')[0];
            // If the subdomain contains a major brand name but the root is untrusted
            if (subdomainPath.includes(brandRoot)) {
                score += 85;
                impersonatingSubdomain = true;
                break;
            }
        }
        
        // Excessively long subdomains
        if (subdomainPath.split('.').length > 3 && !impersonatingSubdomain) {
            score += 25;
        }
    }

    // 5. Typosquatting Analysis (Levenshtein Distance)
    function getLevenshteinDistance(a, b) {
        const matrix = [];
        for (let i = 0; i <= b.length; i++) matrix[i] = [i];
        for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                if (b[i - 1] === a[j - 1]) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }
        return matrix[b.length][a.length];
    }

    let isTypoSquatting = false;
    const actualBaseBrand = rootDomain.split('.')[0];
    for (const brand of trustedDomains) {
        const brandBase = brand.split('.')[0];
        
        // Ensure the brand base is long enough to avoid random false positives (e.g. 'x' vs 'cx')
        if (brandBase.length > 3) {
            const dist = getLevenshteinDistance(brandBase, actualBaseBrand);
            // Distance of 1 or 2 implies heavy visual similarity for medium-to-long words
            if (dist > 0 && dist <= 2) {
                // If it's very similar but not identical, major penalty!
                if (!impersonatingSubdomain) score += 75; 
                isTypoSquatting = true;
                break;
            }
        }
    }

    // 6. Punycode & Homoglyph Attacks
    if (unwwwhostname.includes("xn--")) {
        score += 85; 
    }

    // 7. Suspicious Phishing Keywords
    const suspiciousKeywords = ["login", "secure", "verify", "update", "account", "billing", "support", "auth", "recover", "bank", "payment"];
    let wordMatches = 0;
    suspiciousKeywords.forEach(word => {
        if (unwwwhostname.includes(word)) wordMatches++;
    });
    if (wordMatches > 0) {
        score += (wordMatches * 30);
    }

    // 8. Spam/Risky TLDs
    const riskyTLDs = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "club", "online", "site", "vip", "link"];
    if (riskyTLDs.includes(tld)) {
        score += 40;
    }

    // 9. Anomalous formatting (Multiple hyphens)
    const hyphens = (unwwwhostname.match(/-/g) || []).length;
    if (hyphens >= 2) score += 15;
    if (hyphens >= 4) score += 30;

    // Cap at 100%
    if (score > 100) score = 100;

    // Assign Semantic Status
    let status = "Safe";
    if (score >= 70) {
        status = "Danger";
    } else if (score >= 40) {
        status = "Warning";
    }

    return { score, status };
}