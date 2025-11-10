// Store the original URLs for each tab
const pendingNavigations = new Map();
const allowedNavigations = new Set(); // Track approved navigations

// Flask API endpoint
const FLASK_API_URL = 'http://localhost:5000/checkURL';

// ✅ COMPREHENSIVE WHITELIST OF LEGITIMATE WEBSITES
const LEGITIMATE_DOMAINS = [
  // Search Engines
  'google.com', 'google.co.in', 'google.co.uk', 'bing.com', 'yahoo.com', 
  'duckduckgo.com', 'baidu.com', 'yandex.com', 'ask.com',
  
  // E-commerce
  'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr',
  'ebay.com', 'ebay.in', 'alibaba.com', 'aliexpress.com', 'etsy.com',
  'walmart.com', 'target.com', 'flipkart.com', 'myntra.com', 'ajio.com',
  'snapdeal.com', 'shopify.com', 'bigbasket.com', 'grofers.com', 'jiomart.com',
  
  // Social Media
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
  'reddit.com', 'pinterest.com', 'tumblr.com', 'snapchat.com', 'tiktok.com',
  'whatsapp.com', 'telegram.org', 'discord.com', 'quora.com', 'medium.com',
  
  // Video & Streaming
  'youtube.com', 'netflix.com', 'hulu.com', 'disneyplus.com', 'primevideo.com',
  'hotstar.com', 'zee5.com', 'sonyliv.com', 'voot.com', 'eros-now.com',
  'twitch.tv', 'vimeo.com', 'dailymotion.com', 'hbomax.com',
  
  // Music Streaming
  'spotify.com', 'apple.com', 'music.apple.com', 'pandora.com', 'soundcloud.com',
  'gaana.com', 'jiosaavn.com', 'wynk.in', 'hungama.com', 'amazon.in/music',
  
  // Email Services
  'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com', 'zoho.com',
  'mail.google.com', 'outlook.live.com', 'aol.com', 'icloud.com',
  
  // Cloud Storage
  'drive.google.com', 'dropbox.com', 'onedrive.live.com', 'box.com',
  'mega.nz', 'icloud.com', 'pcloud.com',
  
  // Technology Companies
  'microsoft.com', 'apple.com', 'ibm.com', 'oracle.com', 'adobe.com',
  'salesforce.com', 'sap.com', 'intel.com', 'nvidia.com', 'amd.com',
  'dell.com', 'hp.com', 'lenovo.com', 'asus.com', 'samsung.com',
  
  // Developer Platforms
  'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
  'stackexchange.com', 'npmjs.com', 'pypi.org', 'nuget.org',
  'developer.mozilla.org', 'w3schools.com', 'codepen.io', 'jsfiddle.net',
  
  // Banking & Finance (India)
  'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'pnbindia.in',
  'bankofbaroda.in', 'kotakbank.com', 'yesbank.in', 'idbi.com',
  
  // Banking & Finance (International)
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
  'hsbc.com', 'barclays.co.uk', 'standardchartered.com',
  
  // Payment Services
  'paypal.com', 'stripe.com', 'square.com', 'paytm.com', 'phonepe.com',
  'googlepay.com', 'pay.google.com', 'razorpay.com', 'cashfree.com',
  'instamojo.com', 'venmo.com', 'cashapp.com', 'zelle.com',
  
  // News & Media
  'cnn.com', 'bbc.com', 'bbc.co.uk', 'nytimes.com', 'theguardian.com',
  'reuters.com', 'apnews.com', 'bloomberg.com', 'wsj.com', 'forbes.com',
  'timesofindia.com', 'hindustantimes.com', 'indianexpress.com', 'ndtv.com',
  'thehindu.com', 'news18.com', 'firstpost.com',
  
  // Education
  'wikipedia.org', 'khanacademy.org', 'coursera.org', 'edx.org', 'udemy.com',
  'udacity.com', 'lynda.com', 'skillshare.com', 'pluralsight.com',
  'mit.edu', 'stanford.edu', 'harvard.edu', 'oxford.ac.uk', 'cambridge.org',
  
  // Government (India)
  'india.gov.in', 'uidai.gov.in', 'mygov.in', 'incometax.gov.in',
  'nsdl.com', 'utiitsl.com', 'epfindia.gov.in', 'irctc.co.in',
  'nic.in', 'digitalindia.gov.in', 'meity.gov.in',
  
  // Government (US)
  'usa.gov', 'irs.gov', 'ssa.gov', 'usps.com', 'whitehouse.gov',
  
  // Travel & Transportation
  'makemytrip.com', 'goibibo.com', 'cleartrip.com', 'yatra.com',
  'booking.com', 'expedia.com', 'airbnb.com', 'tripadvisor.com',
  'kayak.com', 'skyscanner.com', 'uber.com', 'ola.com', 'lyft.com',
  
  // Food Delivery
  'zomato.com', 'swiggy.com', 'ubereats.com', 'doordash.com',
  'grubhub.com', 'dominos.com', 'pizzahut.com', 'mcdonalds.com',
  
  // Job Portals
  'linkedin.com', 'naukri.com', 'indeed.com', 'glassdoor.com',
  'monster.com', 'shine.com', 'timesjobs.com', 'foundit.in',
  
  // Utilities & Services
  'zoom.us', 'teams.microsoft.com', 'meet.google.com', 'webex.com',
  'slack.com', 'trello.com', 'asana.com', 'notion.so', 'evernote.com',
  
  // Antivirus & Security
  'norton.com', 'mcafee.com', 'kaspersky.com', 'avg.com', 'avast.com',
  'bitdefender.com', 'malwarebytes.com', 'eset.com',
  
  // Other Popular Services
  'wordpress.com', 'blogger.com', 'wix.com', 'squarespace.com',
  'godaddy.com', 'namecheap.com', 'hostgator.com', 'bluehost.com',
  'cloudflare.com', 'akamai.com', 'fastly.com',
  
  // Cryptocurrency (Major Legitimate Exchanges)
  'coinbase.com', 'binance.com', 'kraken.com', 'gemini.com',
  'wazirx.com', 'coindcx.com', 'zebpay.com',
  
  // Gaming
  'steam.com', 'steampowered.com', 'epicgames.com', 'origin.com',
  'battle.net', 'playstation.com', 'xbox.com', 'nintendo.com',
  'roblox.com', 'minecraft.net', 'ea.com', 'ubisoft.com',
  
  // Web Browsers
  'chrome.google.com', 'mozilla.org', 'firefox.com', 'brave.com',
  'opera.com', 'microsoft.com/edge',
  
  // Mobile App Stores
  'play.google.com', 'apps.apple.com', 'apple.com/app-store',
  
  // CDN & Infrastructure
  'jsdelivr.net', 'unpkg.com', 'cdnjs.com', 'cloudflare.com',
  'akamai.com', 'fastly.net', 'amazonaws.com',
  
  // API & Documentation
  'api.github.com', 'docs.github.com', 'developer.android.com',
  'developers.google.com', 'developer.apple.com', 'docs.microsoft.com',
  
  // Additional Popular Domains
  'canva.com', 'figma.com', 'adobe.com', 'grammarly.com',
  'duolingo.com', 'codecademy.com', 'freecodecamp.org'
];

// 🚨 COMPREHENSIVE PHISHING TERMS DATABASE
const PHISHING_TERMS = [
  // Payment & Money related
  'free-money', 'get-money', 'earn-money', 'free-cash', 'quick-cash',
  'free-paypal', 'get-paypal', 'paypal-free', 'paypal-generator',
  'free-google-pay', 'googlepay-free', 'google-pay-hack',
  'free-phonepe', 'phonepe-free', 'phone-pe-hack',
  'free-paytm', 'paytm-free', 'paytm-cash',
  'bitcoin-free', 'free-bitcoin', 'btc-generator',
  'gift-card-free', 'free-giftcard', 'amazon-gift-free',
  'paypal-money-adder', 'cash-app-free', 'venmo-free',
  
  // Verification & Account scams
  'verify-account', 'account-verify', 'verify-now',
  'confirm-identity', 'verify-identity', 'identity-check',
  'account-suspended', 'suspended-account', 'account-locked',
  'unlock-account', 'reactivate-account', 'restore-account',
  'update-payment', 'payment-failed', 'billing-problem',
  'verify-payment', 'confirm-payment', 'payment-update',
  
  // Login & Security
  'secure-login', 'login-verify', 'verify-login',
  'password-reset', 'reset-password', 'password-expired',
  'security-alert', 'security-warning', 'account-alert',
  'unusual-activity', 'suspicious-activity', 'security-check',
  
  // Prize & Reward scams
  'you-won', 'winner-selected', 'claim-prize',
  'free-iphone', 'free-samsung', 'free-laptop',
  'win-iphone', 'get-free-phone', 'phone-giveaway',
  'claim-reward', 'free-reward', 'reward-waiting',
  'congratulations-winner', 'youve-won', 'lucky-winner',
  
  // Urgency & Action words
  'act-now', 'urgent-action', 'immediate-action',
  'expires-today', 'limited-time', 'offer-expires',
  'click-here-now', 'claim-now', 'download-now',
  'verify-immediately', 'act-immediately',
  
  // Banking & Financial
  'bank-alert', 'banking-security', 'bank-verification',
  'card-verification', 'credit-card-verify', 'debit-card-update',
  'account-details', 'update-details', 'confirm-details',
  
  // Tech Support Scams
  'virus-detected', 'malware-alert', 'computer-infected',
  'system-error', 'windows-alert', 'mac-alert',
  'tech-support', 'support-call', 'call-support',
  
  // Government & Official impersonation
  'irs-refund', 'tax-refund', 'government-refund',
  'stimulus-check', 'covid-relief', 'social-security',
  
  // Streaming & Entertainment
  'netflix-free', 'free-netflix', 'spotify-free',
  'free-spotify', 'youtube-premium-free', 'prime-video-free',
  'disney-plus-free', 'hbo-free', 'streaming-free',
  
  // Gaming
  'free-vbucks', 'vbucks-generator', 'fortnite-free',
  'free-robux', 'robux-generator', 'roblox-free',
  'cod-points-free', 'fifa-coins-free', 'gaming-hack',
  
  // Social Media
  'instagram-followers-free', 'free-followers', 'follower-generator',
  'facebook-hack', 'instagram-hack', 'twitter-hack',
  'account-recovery', 'recover-account', 'get-verified',
  
  // Software & Tools
  'crack', 'keygen', 'serial-key', 'activation-key',
  'license-key-free', 'software-crack', 'windows-activator',
  'office-crack', 'photoshop-free', 'premium-free',
  
  // URL manipulation patterns
  'login-', '-login', 'signin-', '-signin',
  'account-', '-account', 'secure-', '-secure',
  'verify-', '-verify', 'update-', '-update',
  'confirm-', '-confirm', 'suspended-', '-suspended',
  
  // Common typosquatting
  'paypa1', 'g00gle', 'amaz0n', 'micros0ft',
  'app1e', 'netf1ix', 'faceb00k', 'yah00',
  
  // Generic scam words
  'hack-tool', 'generator', 'get-free', 'free-download',
  'no-survey', 'no-verification', 'instant-access',
  'unlimited-free', 'working-hack', '100-working',
  'legit-hack', 'real-hack', 'new-method',
  
  // Phishing specific
  'phish', 'fake-login', 'mirror-site', 'clone-site',
  'redirect-secure', 'auth-required', 'session-expired'
];

// Function to check if URL is in whitelist
function checkWhitelist(url) {
  try {
    const urlObj = new URL(url);
    let hostname = urlObj.hostname.toLowerCase();
    
    // Remove 'www.' prefix if present
    if (hostname.startsWith('www.')) {
      hostname = hostname.substring(4);
    }
    
    // Check if hostname exactly matches any whitelisted domain
    if (LEGITIMATE_DOMAINS.includes(hostname)) {
      console.log('✅ WHITELIST MATCH: Exact match -', hostname);
      return {
        isLegitimate: true,
        matchedDomain: hostname,
        matchType: 'exact'
      };
    }
    
    // Check if hostname is a subdomain of any whitelisted domain
    for (const domain of LEGITIMATE_DOMAINS) {
      if (hostname.endsWith('.' + domain)) {
        console.log('✅ WHITELIST MATCH: Subdomain match -', hostname, 'of', domain);
        return {
          isLegitimate: true,
          matchedDomain: domain,
          matchType: 'subdomain'
        };
      }
    }
    
    console.log('ℹ️ Not in whitelist:', hostname);
    return {
      isLegitimate: false
    };
    
  } catch (error) {
    console.error('Error in whitelist check:', error);
    return {
      isLegitimate: false
    };
  }
}

// Function to check if URL contains phishing terms
function quickPhishingCheck(url) {
  try {
    const urlLower = url.toLowerCase();
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const pathname = urlObj.pathname.toLowerCase();
    const fullPath = (hostname + pathname).toLowerCase();
    
    // Check for phishing terms in URL
    const foundTerms = [];
    
    for (const term of PHISHING_TERMS) {
      const termPattern = term.toLowerCase().replace(/-/g, '[\\-_.]?');
      const regex = new RegExp(termPattern, 'i');
      
      if (regex.test(fullPath) || regex.test(urlLower)) {
        foundTerms.push(term);
      }
    }
    
    if (foundTerms.length > 0) {
      // Generate risk score between 85-95 based on number of terms found
      const baseScore = 85;
      const additionalScore = Math.min(10, foundTerms.length * 2);
      const riskScore = baseScore + additionalScore;
      
      console.log('🚨 PHISHING TERMS DETECTED:', foundTerms);
      console.log('⚡ Quick check - Risk Score:', riskScore);
      
      return {
        isPhishing: true,
        riskScore: riskScore,
        foundTerms: foundTerms,
        quickCheck: true
      };
    }
    
    return {
      isPhishing: false,
      quickCheck: true
    };
    
  } catch (error) {
    console.error('Error in quick phishing check:', error);
    return {
      isPhishing: false,
      quickCheck: true
    };
  }
}

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
    url: url,
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
    // 🎯 STEP 0: Check whitelist first (highest priority)
    console.log('🔍 Checking whitelist...');
    const whitelistCheck = checkWhitelist(url);
    
    if (whitelistCheck.isLegitimate) {
      // Whitelisted domain - mark as safe
      console.log('✅ WHITELISTED DOMAIN - Marking as safe');
      
      siteData.phishing = {
        suspiciousPatterns: [],
        riskScore: 0,
        warnings: [],
        riskLevel: 'SAFE',
        riskColor: '#28a745',
        prediction: 'legitimate',
        isPhishing: false,
        confidence: 100,
        source: 'whitelist',
        whitelistInfo: {
          matched: true,
          domain: whitelistCheck.matchedDomain,
          matchType: whitelistCheck.matchType
        },
        safetyMessage: `✅ This is a verified legitimate website (${whitelistCheck.matchedDomain})`,
        probabilities: {
          phishing: 0.0,
          legitimate: 1.0
        }
      };
      
      console.log('✅ Whitelist phishing data:', siteData.phishing);
      
      // Still get cookies and other data for transparency
      const cookies = await chrome.cookies.getAll({ url: url });
      siteData.cookies = cookies.map(c => ({
        name: c.name,
        domain: c.domain,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite,
        path: c.path
      }));

      const mainDomain = urlObj.hostname;
      siteData.thirdParty = cookies
        .filter(c => !c.domain.includes(mainDomain))
        .map(c => c.domain)
        .filter((v, i, a) => a.indexOf(v) === i);

      siteData.urlAnalysis = {
        length: url.length,
        hasIPAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname),
        subdomainCount: urlObj.hostname.split('.').length - 2,
        hasPort: !!urlObj.port,
        hasQueryParams: !!urlObj.search,
        hasFragment: !!urlObj.hash,
        hasAtSymbol: url.includes('@'),
        hasDoubleSlash: url.indexOf('//', 8) > -1,
        specialCharCount: (url.match(/[@\-?=%&#]/g) || []).length
      };
      
      return siteData;
    }
    
    // Not whitelisted - continue with security checks
    console.log('ℹ️ Not whitelisted - Proceeding with security analysis');
    
    // 🚨 STEP 1: Quick phishing terms check
    console.log('⚡ Running quick phishing terms check...');
    const quickCheck = quickPhishingCheck(url);
    
    if (quickCheck.isPhishing) {
      // Phishing terms detected - skip Flask API call
      console.log('🚨 PHISHING TERMS DETECTED - Skipping Flask API');
      console.log('📊 Terms found:', quickCheck.foundTerms);
      
      siteData.phishing = {
        suspiciousPatterns: quickCheck.foundTerms.map(term => 
          `Phishing keyword detected: "${term}"`
        ),
        riskScore: quickCheck.riskScore,
        warnings: [
          '🚨 HIGH RISK: URL contains known phishing terms',
          `🔍 Detected terms: ${quickCheck.foundTerms.slice(0, 3).join(', ')}${quickCheck.foundTerms.length > 3 ? '...' : ''}`
        ],
        riskLevel: 'CRITICAL',
        riskColor: '#dc3545',
        prediction: 'phishing',
        isPhishing: true,
        confidence: 95,
        source: 'quick-check',
        detectedTerms: quickCheck.foundTerms,
        probabilities: {
          phishing: 0.95,
          legitimate: 0.05
        }
      };
      
      console.log('✅ Quick check phishing data:', siteData.phishing);
      
    } else {
      // No phishing terms - proceed with Flask API
      console.log('✅ No phishing terms detected - Proceeding to Flask API');
      
      const flaskResponse = await checkURLWithFlask(url);
      siteData.flaskAnalysis = flaskResponse;
      
      console.log('📊 Flask Response:', flaskResponse);
      
      if (flaskResponse && !flaskResponse.error) {
        console.log('✅ Using Flask ML analysis');
        
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
      hasDoubleSlash: url.indexOf('//', 8) > -1,
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
  
  if (details.frameId !== 0) return;
  
  if (!details.url.startsWith("http")) {
    console.log("⭐️ Ignoring non-http URL:", details.url);
    return;
  }
  
  const navKey = `${details.tabId}-${details.url}`;
  if (allowedNavigations.has(navKey)) {
    console.log("✅ Navigation is allowed:", navKey);
    allowedNavigations.delete(navKey);
    pendingNavigations.delete(details.tabId);
    return;
  }
  
  if (pendingNavigations.has(details.tabId)) {
    console.log("🧹 Cleaning up previous pending navigation for tab:", details.tabId);
    pendingNavigations.delete(details.tabId);
  }

  const originalUrl = details.url;
  console.log("🔒 Intercepting navigation to:", originalUrl);
  
  console.log("🔍 Starting site analysis...");
  const siteData = await analyzeSiteData(originalUrl);
  console.log("✅ Site data analyzed:", siteData);
  console.log("📊 Risk Score:", siteData.phishing?.riskScore);
  
  pendingNavigations.set(details.tabId, { url: originalUrl, data: siteData });
  
  const confirmPage = chrome.runtime.getURL(
    `confirm.html?data=${encodeURIComponent(JSON.stringify(siteData))}`
  );
  
  console.log("🔄 Navigating to confirmation page");
  chrome.tabs.update(details.tabId, { url: confirmPage });
  
  setTimeout(() => {
    if (pendingNavigations.has(details.tabId)) {
      console.log("⏰ Timeout reached, cleaning up pending navigation for tab:", details.tabId);
      pendingNavigations.delete(details.tabId);
    }
  }, 300000);
});

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
    
    const navKey = `${tabId}-${msg.url}`;
    allowedNavigations.add(navKey);
    console.log("✅ Added to allowed navigations:", navKey);
    
    pendingNavigations.delete(tabId);
    
    chrome.tabs.update(tabId, { url: msg.url }, (tab) => {
      console.log("🚀 Navigation initiated to:", msg.url);
      sendResponse({ success: true });
    });
    
    return true;
    
  } else if (msg.action === "cancel") {
    console.log("🚫 Cancel action for tab", tabId);
    pendingNavigations.delete(tabId);
    chrome.tabs.remove(tabId);
    sendResponse({ success: true });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  console.log("🗑️ Tab removed:", tabId);
  pendingNavigations.delete(tabId);
  for (const key of allowedNavigations) {
    if (key.startsWith(`${tabId}-`)) {
      allowedNavigations.delete(key);
    }
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && pendingNavigations.has(tabId)) {
    console.log("🧹 Cleaning up pending navigation due to tab reload:", tabId);
    pendingNavigations.delete(tabId);
  }
});

console.log("🛡️ Phishing Protection Extension loaded");
console.log(`✅ Whitelist: ${LEGITIMATE_DOMAINS.length} legitimate domains`);
console.log(`🚨 Blacklist: ${PHISHING_TERMS.length} phishing terms`);