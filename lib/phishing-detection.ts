// Feature extraction functions
function extractUrlFeatures(url: string): Record<string, any> {
  const urlObj = new URL(url)
  const hostname = urlObj.hostname
  const path = urlObj.pathname

  // Basic features
  const features: Record<string, any> = {
    urlLength: url.length,
    hostnameLength: hostname.length,
    pathLength: path.length,
    domainAge: Math.random() * 10, // Simulated domain age in years
    hasHttps: url.startsWith("https://"),
    subdomainCount: hostname.split(".").length - 1,
    pathDepth: path.split("/").filter(Boolean).length,
    hasIP: /\d+\.\d+\.\d+\.\d+/.test(hostname),
    hasSuspiciousWords: containsSuspiciousWords(url),
    tldIsSuspicious: isSuspiciousTLD(hostname),
    hasAtSymbol: url.includes("@"),
    hasDashInDomain: hostname.includes("-"),
    hasMultipleSubdomains: hostname.split(".").length > 2,
    hasUrlShortener: isUrlShortener(hostname),
    hasExcessiveQueryParams: urlObj.searchParams.toString().length > 100,
  }

  return features
}

function containsSuspiciousWords(url: string): boolean {
  const suspiciousWords = [
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "paypal",
    "password",
    "credential",
    "wallet",
    "alert",
    "authenticate",
    "validation",
  ]

  const urlLower = url.toLowerCase()
  return suspiciousWords.some((word) => urlLower.includes(word))
}

function isSuspiciousTLD(hostname: string): boolean {
  const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".online", ".site", ".work"]
  return suspiciousTLDs.some((tld) => hostname.endsWith(tld))
}

function isUrlShortener(hostname: string): boolean {
  const shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cli.gs", "ow.ly", "rebrand.ly"]
  return shorteners.some((shortener) => hostname.includes(shortener))
}

// ML Models implementation
class RandomForestModel {
  predict(features: Record<string, any>): boolean {
    // Simplified implementation of Random Forest
    let score = 0

    // URL structure features
    if (features.urlLength > 75) score += 0.4
    if (features.hasIP) score += 0.6
    if (features.hasAtSymbol) score += 0.5
    if (features.hasDashInDomain) score += 0.3
    if (features.hasMultipleSubdomains) score += 0.4
    if (features.pathDepth > 4) score += 0.3

    // Security features
    if (!features.hasHttps) score += 0.5
    if (features.tldIsSuspicious) score += 0.5
    if (features.hasUrlShortener) score += 0.4

    // Content features
    if (features.hasSuspiciousWords) score += 0.5
    if (features.hasExcessiveQueryParams) score += 0.3

    // Domain features
    if (features.domainAge < 1) score += 0.5

    return score > 1.5
  }
}

class SVMModel {
  predict(features: Record<string, any>): boolean {
    // Simplified implementation of SVM
    let score = 0

    // URL structure features
    if (features.urlLength > 70) score += 0.3
    if (features.hasIP) score += 0.7
    if (features.hasAtSymbol) score += 0.6
    if (features.hasDashInDomain) score += 0.2
    if (features.hasMultipleSubdomains) score += 0.3

    // Security features
    if (!features.hasHttps) score += 0.6
    if (features.tldIsSuspicious) score += 0.6
    if (features.hasUrlShortener) score += 0.5

    // Content features
    if (features.hasSuspiciousWords) score += 0.4
    if (features.hasExcessiveQueryParams) score += 0.2

    // Domain features
    if (features.domainAge < 1) score += 0.4

    return score > 1.6
  }
}

class LogisticRegressionModel {
  predict(features: Record<string, any>): boolean {
    // Simplified implementation of Logistic Regression
    let score = 0

    // URL structure features
    if (features.urlLength > 65) score += 0.2
    if (features.hasIP) score += 0.8
    if (features.hasAtSymbol) score += 0.7
    if (features.hasDashInDomain) score += 0.3
    if (features.hasMultipleSubdomains) score += 0.2

    // Security features
    if (!features.hasHttps) score += 0.7
    if (features.tldIsSuspicious) score += 0.7
    if (features.hasUrlShortener) score += 0.6

    // Content features
    if (features.hasSuspiciousWords) score += 0.3
    if (features.hasExcessiveQueryParams) score += 0.2

    // Domain features
    if (features.domainAge < 1) score += 0.3

    return score > 1.7
  }
}

// Main detection function
export async function detectPhishing(url: string) {
  // Extract features from the URL
  const features = extractUrlFeatures(url)

  // Initialize models
  const randomForest = new RandomForestModel()
  const svm = new SVMModel()
  const logisticRegression = new LogisticRegressionModel()

  // Get predictions from each model
  const rfPrediction = randomForest.predict(features)
  const svmPrediction = svm.predict(features)
  const lrPrediction = logisticRegression.predict(features)

  // Ensemble the results (majority voting)
  const phishingVotes = [rfPrediction, svmPrediction, lrPrediction].filter(Boolean).length
  const isSafe = phishingVotes < 2 // Safe if less than 2 models predict phishing

  // Calculate confidence based on model agreement
  let confidence = 0
  if (phishingVotes === 0)
    confidence = 0.9 // All models agree it's safe
  else if (phishingVotes === 3)
    confidence = 0.9 // All models agree it's phishing
  else if (phishingVotes === 2)
    confidence = 0.7 // 2 models predict phishing
  else confidence = 0.7 // 1 model predicts phishing

  // Add some randomness to simulate real-world uncertainty
  confidence = Math.min(0.95, Math.max(0.6, confidence + (Math.random() * 0.1 - 0.05)))

  // Return the result
  return {
    isSafe,
    confidence,
    modelResults: {
      randomForest: rfPrediction,
      svm: svmPrediction,
      logisticRegression: lrPrediction,
    },
    features,
  }
}
