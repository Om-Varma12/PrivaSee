// Store the original URLs for each tab
const pendingNavigations = new Map();
const allowedNavigations = new Set(); // Track approved navigations

// Flask API endpoint
const FLASK_API_URL = 'http://localhost:5000/checkURL';

// Function to check URL with Flask backend
async function checkURLWithFlask(url) {
  try {
    console.log('🔍 Sending URL to Flask API:', url);
    
    const response = await fetch(FLASK_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });
    
    if (!response.ok) {
      throw new Error(`Flask API error: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('✅ Flask API response:', data);
    return data;
    
  } catch (error) {
    console.error('❌ Error calling Flask API:', error);
    return {
      error: true,
      message: error.message,
      fallback: true,
      phishingScore: 0,
      warnings: ['⚠️ Unable to connect to phishing detection service'],
      patterns: []
    };
  }
}

// Function to check for phishing indicators (fallback method)
function analyzePhishingIndicators(url) {
  const indicators = {
    suspiciousPatterns: [],
    riskScore: 0,
    warnings: []
  };
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const path = urlObj.pathname;
    
    // Check for IP address instead of domain
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
      indicators.suspiciousPatterns.push('Using IP address instead of domain name');
      indicators.riskScore += 30;
      indicators.warnings.push('⚠️ Legitimate sites rarely use IP addresses');
    }
    
    // Check for suspicious ports
    const port = urlObj.port;
    if (port && port !== '80' && port !== '443') {
      indicators.suspiciousPatterns.push(`Non-standard port: ${port}`);
      indicators.riskScore += 15;
      indicators.warnings.push('⚠️ Unusual port number detected');
    }
    
    // Check for excessive subdomains
    const subdomains = hostname.split('.');
    if (subdomains.length > 4) {
      indicators.suspiciousPatterns.push(`${subdomains.length} subdomains detected`);
      indicators.riskScore += 20;
      indicators.warnings.push('⚠️ Excessive subdomains (possible phishing)');
    }
    
    // Check for suspicious characters in domain
    if (hostname.includes('@') || hostname.includes('-') && hostname.split('-').length > 3) {
      indicators.suspiciousPatterns.push('Suspicious characters in domain');
      indicators.riskScore += 25;
      indicators.warnings.push('⚠️ Unusual domain characters');
    }
    
    // Check for common phishing keywords
    const phishingKeywords = ['login', 'verify', 'account', 'update', 'secure', 'banking', 'confirm', 'suspend'];
    const foundKeywords = phishingKeywords.filter(keyword => 
      hostname.toLowerCase().includes(keyword) || path.toLowerCase().includes(keyword)
    );
    if (foundKeywords.length > 0) {
      indicators.suspiciousPatterns.push(`Phishing keywords: ${foundKeywords.join(', ')}`);
      indicators.riskScore += foundKeywords.length * 10;
      indicators.warnings.push('⚠️ Contains common phishing keywords');
    }
    
    // Check for typosquatting
    const popularDomains = ['google', 'facebook', 'paypal', 'amazon', 'microsoft', 'apple', 'netflix', 'instagram'];
    for (const domain of popularDomains) {
      if (hostname.includes(domain) && !hostname.endsWith(`${domain}.com`) && !hostname.endsWith(`${domain}.net`)) {
        indicators.suspiciousPatterns.push(`Possible typosquatting: ${domain}`);
        indicators.riskScore += 40;
        indicators.warnings.push(`🚨 May be impersonating ${domain}`);
      }
    }
    
    // Check URL length
    if (url.length > 75) {
      indicators.suspiciousPatterns.push(`Unusually long URL (${url.length} characters)`);
      indicators.riskScore += 10;
    }
    
    // Check for @ symbol
    if (url.includes('@')) {
      indicators.suspiciousPatterns.push('@ symbol in URL (domain hiding technique)');
      indicators.riskScore += 35;
      indicators.warnings.push('🚨 URL contains @ symbol - HIGH RISK');
    }
    
    // Check for excessive dots
    const dotCount = (url.match(/\./g) || []).length;
    if (dotCount > 5) {
      indicators.suspiciousPatterns.push(`Excessive dots in URL (${dotCount})`);
      indicators.riskScore += 15;
    }
  } catch (error) {
    console.error('Error in local phishing analysis:', error);
  }
  
  return indicators;
}

// Function to analyze site data
async function analyzeSiteData(url) {
  const urlObj = new URL(url);
  
  const siteData = {
    url: url,  // ✅ Keep original URL with protocol
    hostname: urlObj.hostname,
    protocol: urlObj.protocol,
    port: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80'),
    pathname: urlObj.pathname,
    search: urlObj.search,
    hash: urlObj.hash,
    permissions: [],
    cookies: [],
    storage: {
      localStorage: false,
      sessionStorage: false,
      indexedDB: false
    },
    apis: [],
    thirdParty: [],
    phishing: null,
    domainAge: 'Unknown',
    certificateInfo: null,
    flaskAnalysis: null
  };

  try {
    // ✅ Send original URL to Flask API (it will clean it internally)
    const flaskResponse = await checkURLWithFlask(url);
    siteData.flaskAnalysis = flaskResponse;
    
    console.log('📊 Flask Response:', flaskResponse);
    
    // Use Flask's analysis if available and successful
    if (flaskResponse && !flaskResponse.error) {
      console.log('✅ Using Flask ML analysis');
      
      // ✅ FIXED: Map Flask response fields correctly
      siteData.phishing = {
        suspiciousPatterns: flaskResponse.patterns || [],
        riskScore: flaskResponse.phishingScore || 0,
        warnings: flaskResponse.warnings || [],
        riskLevel: flaskResponse.riskLevel || 'unknown',
        riskColor: flaskResponse.riskColor || 'gray',
        prediction: flaskResponse.prediction || 'unknown',
        isPhishing: flaskResponse.isPhishing || false,
        confidence: flaskResponse.confidence || 0,
        source: 'flask-ml',
        probabilities: flaskResponse.probabilities || {}
      };
      
      console.log('✅ Mapped phishing data:', siteData.phishing);
      
    } else {
      // Fallback to local heuristic analysis
      console.log('📊 Using local heuristic analysis (Flask unavailable)');
      const localAnalysis = analyzePhishingIndicators(url);
      siteData.phishing = {
        suspiciousPatterns: localAnalysis.suspiciousPatterns,
        riskScore: localAnalysis.riskScore,
        warnings: localAnalysis.warnings,
        source: 'local-heuristic'
      };
    }
    
    // Get cookies for this domain
    const cookies = await chrome.cookies.getAll({ url: url });
    siteData.cookies = cookies.map(c => ({
      name: c.name,
      domain: c.domain,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      path: c.path
    }));

    // Analyze URL for third-party domains
    const mainDomain = urlObj.hostname;
    siteData.thirdParty = cookies
      .filter(c => !c.domain.includes(mainDomain))
      .map(c => c.domain)
      .filter((v, i, a) => a.indexOf(v) === i);

    // Additional URL analysis
    siteData.urlAnalysis = {
      length: url.length,
      hasIPAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname),
      subdomainCount: urlObj.hostname.split('.').length - 2,
      hasPort: !!urlObj.port,
      hasQueryParams: !!urlObj.search,
      hasFragment: !!urlObj.hash,
      hasAtSymbol: url.includes('@'),
      hasDoubleSlash: url.indexOf('//', 8) > -1, // After protocol
      specialCharCount: (url.match(/[@\-?=%&#]/g) || []).length
    };

  } catch (error) {
    console.error('❌ Error analyzing site data:', error);
    if (!siteData.phishing) {
      siteData.phishing = {
        suspiciousPatterns: [],
        riskScore: 0,
        warnings: ['Unable to analyze URL'],
        source: 'error'
      };
    }
  }

  console.log('✅ Final siteData with phishing info:', siteData);
  console.log('📊 Risk Score being sent:', siteData.phishing?.riskScore);
  return siteData;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  console.log("🌐 onBeforeNavigate triggered:", details.url);
  
  // Only handle main frame (not iframes)
  if (details.frameId !== 0) return;
  
  // Ignore extension pages or Chrome internal pages
  if (!details.url.startsWith("http")) {
    console.log("⏭️ Ignoring non-http URL:", details.url);
    return;
  }
  
  // Check if this navigation is allowed (MUST be before showing confirmation)
  const navKey = `${details.tabId}-${details.url}`;
  if (allowedNavigations.has(navKey)) {
    console.log("✅ Navigation is allowed:", navKey);
    allowedNavigations.delete(navKey);
    pendingNavigations.delete(details.tabId);
    return;
  }
  
  // Clean up any existing pending navigation for this tab first
  if (pendingNavigations.has(details.tabId)) {
    console.log("🧹 Cleaning up previous pending navigation for tab:", details.tabId);
    pendingNavigations.delete(details.tabId);
  }

  const originalUrl = details.url;
  console.log("🔒 Intercepting navigation to:", originalUrl);
  
  // Analyze the site data (includes Flask API call)
  console.log("🔍 Starting site analysis...");
  const siteData = await analyzeSiteData(originalUrl);
  console.log("✅ Site data analyzed:", siteData);
  console.log("📊 Risk Score:", siteData.phishing?.riskScore);
  
  // Store the original URL and data
  pendingNavigations.set(details.tabId, { url: originalUrl, data: siteData });
  
  // Navigate to the confirmation page with encoded data
  const confirmPage = chrome.runtime.getURL(
    `confirm.html?data=${encodeURIComponent(JSON.stringify(siteData))}`
  );
  
  console.log("📄 Navigating to confirmation page");
  chrome.tabs.update(details.tabId, { url: confirmPage });
  
  // Set a timeout to clean up if user doesn't respond within 5 minutes
  setTimeout(() => {
    if (pendingNavigations.has(details.tabId)) {
      console.log("⏰ Timeout reached, cleaning up pending navigation for tab:", details.tabId);
      pendingNavigations.delete(details.tabId);
    }
  }, 300000); // 5 minutes
});

// Listen for messages from confirm.html
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log("📨 Received message:", msg);
  const tabId = sender.tab?.id;
  
  if (!tabId) {
    console.error("❌ No tab ID in sender");
    sendResponse({ error: "No tab ID" });
    return;
  }
  
  if (msg.action === "continue") {
    console.log("✅ Continue action for tab", tabId, "to URL:", msg.url);
    
    if (!msg.url) {
      console.error("❌ No URL provided in continue message");
      sendResponse({ error: "No URL provided" });
      return;
    }
    
    // Mark this navigation as allowed BEFORE navigating
    const navKey = `${tabId}-${msg.url}`;
    allowedNavigations.add(navKey);
    console.log("✅ Added to allowed navigations:", navKey);
    
    // Remove from pending
    pendingNavigations.delete(tabId);
    
    // Navigate to the URL
    chrome.tabs.update(tabId, { url: msg.url }, (tab) => {
      console.log("🚀 Navigation initiated to:", msg.url);
      sendResponse({ success: true });
    });
    
    return true; // Keep message channel open for async response
    
  } else if (msg.action === "cancel") {
    console.log("🚫 Cancel action for tab", tabId);
    // Remove from pending and close tab
    pendingNavigations.delete(tabId);
    chrome.tabs.remove(tabId);
    sendResponse({ success: true });
  }
});

// Clean up closed tabs
chrome.tabs.onRemoved.addListener((tabId) => {
  console.log("🗑️ Tab removed:", tabId);
  pendingNavigations.delete(tabId);
  // Clean up any allowed navigations for this tab
  for (const key of allowedNavigations) {
    if (key.startsWith(`${tabId}-`)) {
      allowedNavigations.delete(key);
    }
  }
});

// Add cleanup for tab updates to prevent stuck states
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // If tab is loading and we have a pending navigation, clean it up
  if (changeInfo.status === 'loading' && pendingNavigations.has(tabId)) {
    console.log("🧹 Cleaning up pending navigation due to tab reload:", tabId);
    pendingNavigations.delete(tabId);
  }
});

console.log("🛡️ Phishing Protection Extension loaded and active");