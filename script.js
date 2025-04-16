document.addEventListener("DOMContentLoaded", () => {
  // Set current year in footer
  var currentYearElement = document.getElementById("current-year")
  if (currentYearElement) {
    currentYearElement.textContent = new Date().getFullYear()
  }

  // Form submission
  var urlForm = document.getElementById("url-form")
  var urlInput = document.getElementById("url")
  var analyzeBtn = document.getElementById("analyze-btn")
  var btnText = document.querySelector(".btn-text")
  var btnLoading = document.querySelector(".btn-loading")
  var errorMessage = document.getElementById("error-message")
  var errorText = document.getElementById("error-text")
  var resultContainer = document.getElementById("result-container")

  // Tab functionality
  var tabTriggers = document.querySelectorAll(".tab-trigger")
  var tabContents = document.querySelectorAll(".tab-content")

  if (tabTriggers.length > 0) {
    tabTriggers.forEach((trigger) => {
      trigger.addEventListener("click", () => {
        // Remove active class from all triggers and contents
        tabTriggers.forEach((t) => {
          t.classList.remove("active")
        })
        tabContents.forEach((c) => {
          c.classList.remove("active")
        })

        // Add active class to clicked trigger and corresponding content
        trigger.classList.add("active")
        var tabId = trigger.getAttribute("data-tab")
        var tabContent = document.getElementById(tabId + "-tab")
        if (tabContent) {
          tabContent.classList.add("active")
        }
      })
    })
  }

  // Form submission handler
  if (urlForm) {
    urlForm.addEventListener("submit", (e) => {
      e.preventDefault()

      if (!urlInput) return
      var url = urlInput.value.trim()

      if (!url) {
        showError("Please enter a URL")
        return
      }

      // Show loading state
      setLoading(true)
      hideError()
      hideResult()

      // Simulate API call with timeout
      setTimeout(() => {
        try {
          // Prepare URL for API call
          var urlToCheck = url
          if (!url.startsWith("http://") && !url.startsWith("https://")) {
            urlToCheck = "https://" + url
          }

          // Validate URL format
          try {
            new URL(urlToCheck)
          } catch (e) {
            showError("Please enter a valid URL")
            setLoading(false)
            return
          }

          // Simulate result
          var result = simulateAnalysis(urlToCheck)
          displayResult(result, urlToCheck)
        } catch (error) {
          console.error("Error:", error)
          showError("An error occurred while analyzing the URL. Please try again.")
        } finally {
          setLoading(false)
        }
      }, 1500)
    })
  }

  // Helper functions
  function setLoading(isLoading) {
    if (!btnText || !btnLoading || !analyzeBtn) return

    if (isLoading) {
      btnText.classList.add("hidden")
      btnLoading.classList.remove("hidden")
      analyzeBtn.disabled = true
    } else {
      btnText.classList.remove("hidden")
      btnLoading.classList.add("hidden")
      analyzeBtn.disabled = false
    }
  }

  function showError(message) {
    if (!errorText || !errorMessage) return
    errorText.textContent = message
    errorMessage.classList.remove("hidden")
  }

  function hideError() {
    if (!errorMessage) return
    errorMessage.classList.add("hidden")
  }

  function hideResult() {
    if (!resultContainer) return
    resultContainer.classList.add("hidden")
  }

  function simulateAnalysis(url) {
    // This is a simplified simulation
    var isSuspicious =
      url.includes("login") ||
      url.includes("secure") ||
      url.includes("account") ||
      url.includes("verify") ||
      url.includes("paypal") ||
      url.includes("signin") ||
      !url.startsWith("https://")

    var randomForest = isSuspicious
    var svm = Math.random() > 0.3 ? isSuspicious : !isSuspicious
    var logisticRegression = Math.random() > 0.3 ? isSuspicious : !isSuspicious

    var phishingVotes = [randomForest, svm, logisticRegression].filter(Boolean).length
    var isSafe = phishingVotes < 2

    var confidence = 0
    if (phishingVotes === 0) confidence = 0.9
    else if (phishingVotes === 3) confidence = 0.9
    else if (phishingVotes === 2) confidence = 0.7
    else confidence = 0.7

    confidence = Math.min(0.95, Math.max(0.6, confidence + (Math.random() * 0.1 - 0.05)))

    return {
      isSafe: isSafe,
      confidence: confidence,
      modelResults: {
        randomForest: randomForest,
        svm: svm,
        logisticRegression: logisticRegression,
      },
      features: {
        urlLength: url.length,
        hasHttps: url.startsWith("https://"),
        hasSuspiciousWords: isSuspicious,
        domainAge: Math.round(Math.random() * 10 * 10) / 10,
        hasAtSymbol: url.includes("@"),
        hasDashInDomain: url.split("//")[1].split("/")[0].includes("-"),
        pathDepth: url.split("/").length - 3,
      },
    }
  }

  function displayResult(result, url) {
    if (!resultContainer) return

    // Set up result alert
    var resultAlert = document.getElementById("result-alert")
    var resultIcon = document.getElementById("result-icon")
    var resultTitle = document.getElementById("result-title")
    var resultDescription = document.getElementById("result-description")

    if (!resultAlert || !resultIcon || !resultTitle || !resultDescription) return

    if (result.isSafe) {
      resultAlert.className = "alert alert-success"
      resultIcon.className = "fas fa-check-circle"
      resultTitle.textContent = "Safe URL Detected"
      resultDescription.textContent = "This URL appears to be legitimate based on our analysis."
    } else {
      resultAlert.className = "alert alert-danger"
      resultIcon.className = "fas fa-shield-alt"
      resultTitle.textContent = "Potential Phishing Detected"
      resultDescription.textContent = "This URL shows characteristics commonly associated with phishing attempts."
    }

    // Set up summary tab
    var confidenceScore = document.getElementById("confidence-score")
    var confidenceBar = document.getElementById("confidence-bar")
    var summaryUrl = document.getElementById("summary-url")
    var analysisDate = document.getElementById("analysis-date")

    if (confidenceScore) confidenceScore.textContent = Math.round(result.confidence * 100) + "%"
    if (confidenceBar) {
      confidenceBar.style.width = Math.round(result.confidence * 100) + "%"
      confidenceBar.style.backgroundColor = result.isSafe ? "var(--success-color)" : "var(--danger-color)"
    }
    if (summaryUrl) summaryUrl.textContent = url
    if (analysisDate) analysisDate.textContent = new Date().toLocaleString()

    // Set up models tab
    var rfResult = document.getElementById("rf-result")
    var svmResult = document.getElementById("svm-result")
    var lrResult = document.getElementById("lr-result")

    if (rfResult) setModelResult(rfResult, result.modelResults.randomForest)
    if (svmResult) setModelResult(svmResult, result.modelResults.svm)
    if (lrResult) setModelResult(lrResult, result.modelResults.logisticRegression)

    // Set up features tab
    var featuresList = document.getElementById("features-list")
    if (featuresList) {
      featuresList.innerHTML = ""

      for (var key in result.features) {
        if (result.features.hasOwnProperty(key)) {
          var value = result.features[key]

          var featureItem = document.createElement("div")
          featureItem.className = "feature-item"

          var label = document.createElement("span")
          label.className = "label"
          label.textContent = formatFeatureName(key) + ":"

          var valueSpan = document.createElement("span")
          valueSpan.className = "value"
          valueSpan.textContent = typeof value === "boolean" ? (value ? "Yes" : "No") : value.toString()

          featureItem.appendChild(label)
          featureItem.appendChild(valueSpan)
          featuresList.appendChild(featureItem)
        }
      }
    }

    // Show result container
    resultContainer.classList.remove("hidden")

    // Reset to first tab
    if (tabTriggers.length > 0) {
      tabTriggers[0].click()
    }
  }

  function setModelResult(element, isPhishing) {
    element.textContent = isPhishing ? "PHISHING" : "SAFE"
    element.className = isPhishing ? "badge badge-danger" : "badge badge-success"
  }

  function formatFeatureName(name) {
    return name.replace(/([A-Z])/g, " $1").replace(/^./, (str) => str.toUpperCase())
  }
})
