export function analyzeURL(url) {
    let score = 0;

    function getDomain(url) {
        try {
            const parsed = new URL(url);
            return parsed.hostname.replace(/^www\./, "").toLowerCase();
        } catch {
            return "";
        }
    }

    function levenshtein(a, b) {
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

    const domain = getDomain(url);

    const trustedBrands = [
        "google.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
        "linkedin.com", "youtube.com", "microsoft.com", "apple.com",
        "paypal.com", "paytm.com", "phonepe.com", "gpay.com", "googlepay.com",
        "upi.com", "visa.com", "mastercard.com",
        "amazon.com", "flipkart.com", "ebay.com", "aliexpress.com", "meesho.com",
        "gmail.com", "outlook.com", "yahoo.com", "icloud.com",
        "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
        "netflix.com", "hotstar.com", "primevideo.com",
        "github.com", "stackoverflow.com", "vercel.com"
    ];

    const phishingWords = ["login", "secure", "verify", "account", "bank", "update"];

    if (url.startsWith("http://")) score += 50;
    if (url.length > 75) score += 25;
    if (url.includes("@")) score += 50;
    if (url.includes("-")) score += 20;
    if (domain.split(".").length > 3) score += 30;

    trustedBrands.forEach(brand => {
        const cleanBrand = brand.split(".")[0];

        const hasBrand = domain.includes(cleanBrand);
        const isOfficial = domain.endsWith(brand);

        if (hasBrand && !isOfficial) {
            score += 80;

            phishingWords.forEach(word => {
                if (domain.includes(word) || url.includes(word)) {
                    score += 60;
                }
            });
        }

        const dist = levenshtein(domain, cleanBrand);
        if (dist > 0 && dist <= 3) {
            score += 70;
        }
    });

    if (/[0-9]/.test(domain)) score += 30;

    phishingWords.forEach(word => {
        if (url.includes(word)) score += 20;
    });

    const riskyTLDs = [".co", ".xyz", ".top", ".tk", ".ml", ".ga"];
    riskyTLDs.forEach(tld => {
        if (domain.endsWith(tld)) {
            score += 50;
        }
    });

    if (
        (domain.includes("login") && domain.includes("secure")) ||
        (domain.includes("verify") && domain.includes("account"))
    ) {
        score += 70;
    }

    if (score > 100) score = 100;

    let status = "Safe";
    if (score >= 70) status = "High Risk";
    else if (score >= 40) status = "Suspicious";

    return { score, status };
}