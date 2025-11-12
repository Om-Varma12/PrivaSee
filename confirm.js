const urlParams = new URLSearchParams(window.location.search);
const dataParam = urlParams.get("data");
let siteData = null;
let originalUrl = "";

console.log("Raw data param:", dataParam);

try {
  const decodedData = decodeURIComponent(dataParam);
  console.log("Decoded data:", decodedData);
  
  siteData = JSON.parse(decodedData);
  originalUrl = siteData.url;
  
  console.log("Parsed site data:", siteData);
  console.log("Original URL:", originalUrl);
  console.log("Phishing data:", siteData.phishing);
  
  // Ensure we have the correct protocol from the original URL
  if (siteData.url) {
    try {
      const urlObj = new URL(siteData.url);
      siteData.protocol = urlObj.protocol;
      siteData.hostname = urlObj.hostname;
      console.log("Protocol from URL:", siteData.protocol);
      console.log("Hostname from URL:", siteData.hostname);
    } catch (error) {
      console.error("Error parsing URL:", error);
      siteData.protocol = "unknown:";
      siteData.hostname = "Unknown";
    }
  }
} catch (e) {
  console.error("Error parsing site data:", e);
  console.error("Failed data:", dataParam);
  siteData = { 
    hostname: "Unknown", 
    url: "", 
    protocol: "unknown:", 
    phishing: { riskScore: 0 } 
  };
}

// Calculate overall risk level - FIXED: Check all possible score locations
let riskScore = 0;

if (siteData.phishing) {
  // Try different possible locations for the risk score
  riskScore = siteData.phishing.riskScore || 
              siteData.phishing.phishingScore || 
              0;
  
  console.log("Raw phishing object:", JSON.stringify(siteData.phishing, null, 2));
  console.log("Extracted risk score:", riskScore);
  
  // Additional debugging
  // if (riskScore === 0 && siteData.phishing) {
  //   console.error("⚠️ Risk score is 0 but phishing object exists!");
  //   console.error("Phishing keys:", Object.keys(siteData.phishing));
  //   console.error("Full phishing object:", siteData.phishing);
  // }
} else {
  console.warn("No phishing data found in siteData");
}

let riskLevel = 'LOW';
let riskColor = '#28a745';
let riskIcon = '✓';
let riskBgColor = '#28a74515';

// Check if this is a whitelisted/safe site
const isWhitelisted = siteData.phishing?.source === 'whitelist';

if (isWhitelisted) {
  riskLevel = 'SAFE';
  riskColor = '#28a745';
  riskIcon = '✅';
  riskBgColor = '#28a74520';
} else if (riskScore > 70) {
  riskLevel = 'CRITICAL';
  riskColor = '#dc3545';
  riskIcon = '🚨';
  riskBgColor = '#dc354515';
} else if (riskScore > 50) {
  riskLevel = 'HIGH';
  riskColor = '#ff6b6b';
  riskIcon = '⚠️';
  riskBgColor = '#ff6b6b15';
} else if (riskScore > 30) {
  riskLevel = 'MEDIUM';
  riskColor = '#ffc107';
  riskIcon = '⚠️';
  riskBgColor = '#ffc10715';
}

console.log("Final risk assessment:", { riskScore, riskLevel, riskColor });

// Update header based on risk
const container = document.querySelector('.container');
const icon = document.querySelector('.icon');
const title = document.querySelector('h1');

icon.textContent = riskIcon;
if (riskScore > 50) {
  container.style.borderTop = `5px solid ${riskColor}`;
  title.innerHTML = `⚠️ HIGH RISK DETECTED - ${riskLevel}`;
  title.style.color = riskColor;
}

// Update site name - FIXED: Better fallback chain
const displayHostname = siteData.hostname || 
                        (siteData.url ? new URL(siteData.url).hostname : "Unknown");
document.getElementById("site-name").innerText = displayHostname;
console.log("Displaying hostname:", displayHostname);

// Add risk score display with dynamic styling
const riskDisplay = document.createElement('div');
riskDisplay.style.cssText = `
  background: ${riskBgColor};
  border: 2px solid ${riskColor};
  padding: 15px;
  border-radius: 8px;
  margin: 20px 0;
  text-align: center;
`;
riskDisplay.innerHTML = `
  <div style="font-size: 32px; font-weight: bold; color: ${riskColor};">${riskScore}/100</div>
  <div style="font-size: 14px; color: #666; margin-top: 5px;">RISK SCORE - ${riskLevel}</div>
`;
document.querySelector('.site-name').after(riskDisplay);

// Function to create collapsible sections
function createCollapsibleSection(title, content, isWarning = false, isExpanded = false) {
  const section = document.createElement('div');
  section.className = 'data-section';
  
  const header = document.createElement('h3');
  header.className = isExpanded ? 'collapsible' : 'collapsible collapsed';
  header.innerHTML = title;
  
  const contentDiv = document.createElement('div');
  contentDiv.className = isExpanded ? 'collapsible-content' : 'collapsible-content collapsed';
  contentDiv.innerHTML = content;
  
  header.addEventListener('click', () => {
    header.classList.toggle('collapsed');
    contentDiv.classList.toggle('collapsed');
  });
  
  section.appendChild(header);
  section.appendChild(contentDiv);
  
  return section;
}

// Render the data
const dataContainer = document.getElementById('data-container');

// 1. PHISHING ANALYSIS (Most important - show first and expanded if risky)
if (siteData.phishing) {
  const phishing = siteData.phishing;
  let phishingHTML = '';
  
  console.log("Rendering phishing data:", phishing);
  
  // Show ML prediction if available
  if (phishing.prediction) {
    const predictionClass = phishing.isPhishing ? 'danger' : 'safe';
    phishingHTML += `<div class="data-item ${predictionClass}">
      <strong>ML Prediction:</strong> ${phishing.prediction.toUpperCase()}
      ${phishing.confidence ? ` (${phishing.confidence}% confidence)` : ''}
    </div>`;
  }
  
  // Show detected terms if from quick check
  if (phishing.detectedTerms && phishing.detectedTerms.length > 0) {
    phishingHTML += '<div class="data-item danger"><strong>🚨 Phishing Terms Detected:</strong></div>';
    phishing.detectedTerms.slice(0, 10).forEach(term => {
      phishingHTML += `<div class="data-item danger">• ${term}</div>`;
    });
    if (phishing.detectedTerms.length > 10) {
      phishingHTML += `<div class="empty-state">... and ${phishing.detectedTerms.length - 10} more terms</div>`;
    }
  }
  
  // Show warnings
  if (phishing.warnings && phishing.warnings.length > 0) {
    phishingHTML += '<div style="margin-bottom: 15px;">';
    phishing.warnings.forEach(warning => {
      phishingHTML += `<div class="data-item danger">🚨 ${warning}</div>`;
    });
    phishingHTML += '</div>';
  }
  
  // Show suspicious patterns
  if (phishing.suspiciousPatterns && phishing.suspiciousPatterns.length > 0) {
    phishingHTML += '<div class="data-item warning"><strong>⚠️ Suspicious Patterns Detected:</strong></div>';
    phishing.suspiciousPatterns.forEach(pattern => {
      phishingHTML += `<div class="data-item warning">${pattern}</div>`;
    });
  } else if (riskScore < 30) {
    phishingHTML += '<div class="data-item safe">✓ No obvious phishing patterns detected</div>';
  }
  
  // Show probabilities if available
  if (phishing.probabilities) {
    phishingHTML += '<div class="data-item"><strong>Model Confidence:</strong></div>';
    Object.entries(phishing.probabilities).forEach(([label, prob]) => {
      const percentage = (prob * 100).toFixed(1);
      phishingHTML += `<div class="data-item">
        ${label}: ${percentage}%
        <div style="background: #e0e0e0; height: 8px; border-radius: 4px; margin-top: 4px;">
          <div style="background: ${label === 'phishing' ? '#dc3545' : '#28a745'}; width: ${percentage}%; height: 100%; border-radius: 4px;"></div>
        </div>
      </div>`;
    });
  }
  
  // Show analysis source
  if (phishing.source) {
    const sourceLabels = {
      'flask-ml': 'Machine Learning Model',
      'local-heuristic': 'Local Heuristic Analysis',
      'quick-check': 'Quick Pattern Matching',
      'error': 'Error During Analysis'
    };
    const sourceLabel = sourceLabels[phishing.source] || phishing.source;
    phishingHTML += `<div class="data-item"><small><em>Analysis by: ${sourceLabel}</em></small></div>`;
  }
  
  if (!phishingHTML) {
    phishingHTML = '<div class="data-item">No phishing analysis data available</div>';
  }
  
  dataContainer.appendChild(createCollapsibleSection('🛡️ Phishing Analysis', phishingHTML, true, riskScore > 30));
} else {
  console.warn("No phishing data to render");
  const noPhishingData = '<div class="data-item warning">⚠️ Phishing analysis data not available</div>';
  dataContainer.appendChild(createCollapsibleSection('🛡️ Phishing Analysis', noPhishingData, true, true));
}

// 2. SSL CERTIFICATE INFORMATION
if (siteData.certificate) {
  const cert = siteData.certificate;
  let certHTML = '';
  
  if (cert.valid) {
    certHTML += `<div class="data-item safe">✓ Valid SSL Certificate</div>`;
  } else {
    certHTML += `<div class="data-item danger">⚠️ Invalid or No SSL Certificate</div>`;
  }
  
  if (cert.issuer) {
    certHTML += `<div class="data-item"><strong>Issuer:</strong> ${cert.issuer}</div>`;
  }
  
  if (cert.subject) {
    certHTML += `<div class="data-item"><strong>Issued To:</strong> ${cert.subject}</div>`;
  }
  
  if (cert.validFrom) {
    certHTML += `<div class="data-item"><strong>Valid From:</strong> ${new Date(cert.validFrom * 1000).toLocaleDateString()}</div>`;
  }
  
  if (cert.validTo) {
    const expiryDate = new Date(cert.validTo * 1000);
    const daysUntilExpiry = Math.floor((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
    const isExpiringSoon = daysUntilExpiry < 30;
    
    certHTML += `<div class="data-item ${isExpiringSoon ? 'warning' : ''}">
      <strong>Valid Until:</strong> ${expiryDate.toLocaleDateString()}
      ${isExpiringSoon ? `<span class="badge badge-warning">Expires in ${daysUntilExpiry} days</span>` : ''}
    </div>`;
  }
  
  if (cert.protocol) {
    certHTML += `<div class="data-item"><strong>Protocol:</strong> ${cert.protocol}</div>`;
  }
  
  if (cert.keyExchange) {
    certHTML += `<div class="data-item"><strong>Key Exchange:</strong> ${cert.keyExchange}</div>`;
  }
  
  dataContainer.appendChild(createCollapsibleSection('🔒 SSL Certificate', certHTML, !cert.valid, true));
} else if (siteData.protocol === 'https:') {
  const noCertInfo = '<div class="data-item warning">⚠️ HTTPS detected but certificate details not available</div>';
  dataContainer.appendChild(createCollapsibleSection('🔒 SSL Certificate', noCertInfo, true, true));
}

// 3. DOMAIN INFORMATION
if (siteData.domainInfo) {
  const domain = siteData.domainInfo;
  let domainHTML = '';
  
  if (domain.age !== undefined) {
    const isNewDomain = domain.age < 180; // Less than 6 months
    domainHTML += `<div class="data-item ${isNewDomain ? 'warning' : 'safe'}">
      <strong>Domain Age:</strong> ${domain.age} days (${Math.floor(domain.age / 365)} years, ${Math.floor((domain.age % 365) / 30)} months)
      ${isNewDomain ? '<span class="badge badge-warning">New Domain</span>' : ''}
    </div>`;
  }
  
  if (domain.createdDate) {
    domainHTML += `<div class="data-item"><strong>Created:</strong> ${new Date(domain.createdDate).toLocaleDateString()}</div>`;
  }
  
  if (domain.expiryDate) {
    domainHTML += `<div class="data-item"><strong>Expires:</strong> ${new Date(domain.expiryDate).toLocaleDateString()}</div>`;
  }
  
  if (domain.registrar) {
    domainHTML += `<div class="data-item"><strong>Registrar:</strong> ${domain.registrar}</div>`;
  }
  
  if (domain.registrant) {
    domainHTML += `<div class="data-item"><strong>Registrant:</strong> ${domain.registrant}</div>`;
  }
  
  if (domain.privacyProtected !== undefined) {
    domainHTML += `<div class="data-item ${domain.privacyProtected ? 'warning' : ''}">
      <strong>Privacy Protected:</strong> ${domain.privacyProtected ? '⚠️ Yes (Owner hidden)' : '✓ No'}
    </div>`;
  }
  
  dataContainer.appendChild(createCollapsibleSection('📋 Domain Registration', domainHTML, false, domain.age < 180));
}

// 4. URL DETAILS
let urlHTML = `
  <div class="data-item">
    <strong>Full URL:</strong><br>
    <small style="word-break: break-all;">${siteData.url}</small>
  </div>
  <div class="data-item">
    <strong>Hostname:</strong> ${displayHostname}
  </div>
  <div class="data-item">
    <strong>Port:</strong> ${siteData.port}
    ${siteData.port !== '443' && siteData.port !== '80' ? '<span class="badge badge-warning">Non-standard</span>' : ''}
  </div>
  <div class="data-item">
    <strong>Path:</strong> ${siteData.pathname || '/'}
  </div>
`;

if (siteData.search) {
  urlHTML += `<div class="data-item"><strong>Query Parameters:</strong> ${siteData.search}</div>`;
}

if (siteData.urlAnalysis) {
  const analysis = siteData.urlAnalysis;
  urlHTML += `
    <div class="data-item">
      <strong>URL Length:</strong> ${analysis.length} characters
      ${analysis.length > 75 ? '<span class="badge badge-warning">Unusually long</span>' : ''}
    </div>
    <div class="data-item ${analysis.hasIPAddress ? 'danger' : 'safe'}">
      <strong>Using IP Address:</strong> ${analysis.hasIPAddress ? '⚠️ Yes (Suspicious)' : '✓ No'}
    </div>
    <div class="data-item ${analysis.subdomainCount > 3 ? 'warning' : ''}">
      <strong>Subdomain Count:</strong> ${analysis.subdomainCount}
      ${analysis.subdomainCount > 3 ? '<span class="badge badge-warning">Many subdomains</span>' : ''}
    </div>
    <div class="data-item ${analysis.hasAtSymbol ? 'danger' : ''}">
      <strong>@ Symbol in URL:</strong> ${analysis.hasAtSymbol ? '⚠️ Yes (Phishing indicator)' : '✓ No'}
    </div>
    <div class="data-item ${analysis.hasDoubleSlash ? 'warning' : ''}">
      <strong>Double Slash in Path:</strong> ${analysis.hasDoubleSlash ? '⚠️ Yes' : '✓ No'}
    </div>
    <div class="data-item">
      <strong>Special Characters:</strong> ${analysis.specialCharCount}
    </div>
  `;
}

dataContainer.appendChild(createCollapsibleSection('🔗 URL Analysis', urlHTML, false, true));

// 5. Protocol & Connection Info
const isSecure = siteData.protocol === 'https:';
let protocolInfo = `
  <div class="data-item ${isSecure ? 'safe' : 'danger'}">
    <strong>Protocol:</strong> ${isSecure ? '🔒 HTTPS (Encrypted)' : '⚠️ HTTP (Not Encrypted)'}
  </div>
  ${!isSecure ? '<div class="data-item danger">🚨 This site does NOT use encryption. Your data can be intercepted!</div>' : ''}
`;

if (siteData.securityState) {
  const state = siteData.securityState;
  protocolInfo += `<div class="data-item"><strong>Security State:</strong> ${state}</div>`;
}

dataContainer.appendChild(createCollapsibleSection('🔐 Connection Security', protocolInfo, !isSecure, !isSecure));

// 6. Cookies
if (siteData.cookies && siteData.cookies.length > 0) {
  let cookiesHTML = `<div class="data-item warning">
    <span class="badge badge-warning">${siteData.cookies.length}</span> cookies detected
  </div>`;
  
  const insecureCookies = siteData.cookies.filter(c => !c.secure || !c.httpOnly).length;
  if (insecureCookies > 0) {
    cookiesHTML += `<div class="data-item danger">⚠️ ${insecureCookies} cookies lack security flags</div>`;
  }
  
  siteData.cookies.forEach((cookie, i) => {
    if (i < 10) {
      const flags = [];
      if (cookie.secure) flags.push('🔒 Secure');
      if (cookie.httpOnly) flags.push('🛡️ HttpOnly');
      if (cookie.sameSite) flags.push(`SameSite=${cookie.sameSite}`);
      
      const isInsecure = !cookie.secure || !cookie.httpOnly;
      
      cookiesHTML += `
        <div class="data-item ${isInsecure ? 'warning' : ''}">
          <strong>${cookie.name}</strong><br>
          <small>Domain: ${cookie.domain} | Path: ${cookie.path}</small><br>
          <small>${flags.length > 0 ? flags.join(', ') : '⚠️ No security flags'}</small>
        </div>
      `;
    }
  });
  
  if (siteData.cookies.length > 10) {
    cookiesHTML += `<div class="empty-state">... and ${siteData.cookies.length - 10} more cookies</div>`;
  }
  
  dataContainer.appendChild(createCollapsibleSection('🍪 Cookies', cookiesHTML, insecureCookies > 0));
} else {
  const noCookies = '<div class="data-item safe">✓ No cookies detected (yet)</div>';
  dataContainer.appendChild(createCollapsibleSection('🍪 Cookies', noCookies));
}

// 7. Third-party Domains & Trackers
if (siteData.thirdParty && siteData.thirdParty.length > 0) {
  let thirdPartyHTML = `<div class="data-item danger">
    <span class="badge badge-danger">${siteData.thirdParty.length}</span> third-party domains detected
  </div>`;
  
  siteData.thirdParty.slice(0, 15).forEach(domain => {
    thirdPartyHTML += `<div class="data-item">🌐 ${domain}</div>`;
  });
  
  if (siteData.thirdParty.length > 15) {
    thirdPartyHTML += `<div class="empty-state">... and ${siteData.thirdParty.length - 15} more</div>`;
  }
  
  dataContainer.appendChild(createCollapsibleSection('🌐 Third-party Connections', thirdPartyHTML, true));
} else {
  const noThirdParty = '<div class="data-item safe">✓ No third-party domains detected</div>';
  dataContainer.appendChild(createCollapsibleSection('🌐 Third-party Connections', noThirdParty));
}

// Update button text and show alerts based on risk
if (riskScore > 70) {
  document.getElementById("yes-btn").innerHTML = '⚠️ Continue Anyway (Not Recommended)';
  document.getElementById("yes-btn").style.backgroundColor = '#ff6b6b';
  
  // Show critical alert
  const alertDiv = document.createElement('div');
  alertDiv.style.cssText = `
    background: #fff3cd;
    border: 2px solid #ffc107;
    border-left: 5px solid #dc3545;
    padding: 15px;
    border-radius: 8px;
    margin: 20px 0;
    text-align: left;
  `;
  alertDiv.innerHTML = `
    <div style="display: flex; align-items: start; gap: 10px;">
      <div style="font-size: 24px;">🚨</div>
      <div>
        <strong style="color: #dc3545; font-size: 16px;">CRITICAL WARNING</strong>
        <p style="margin: 8px 0 0 0; color: #856404;">
          This website shows multiple signs of being dangerous. We strongly recommend NOT proceeding.
          Your personal information, passwords, and financial data may be at risk.
        </p>
      </div>
    </div>
  `;
  document.querySelector('.site-name').after(alertDiv);
  
} else if (riskScore > 50) {
  const alertDiv = document.createElement('div');
  alertDiv.style.cssText = `
    background: #fff3cd;
    border: 2px solid #ffc107;
    border-left: 5px solid #ff9800;
    padding: 15px;
    border-radius: 8px;
    margin: 20px 0;
    text-align: left;
  `;
  alertDiv.innerHTML = `
    <div style="display: flex; align-items: start; gap: 10px;">
      <div style="font-size: 24px;">⚠️</div>
      <div>
        <strong style="color: #ff6b6b; font-size: 16px;">HIGH RISK WARNING</strong>
        <p style="margin: 8px 0 0 0; color: #856404;">
          This website has suspicious characteristics. Exercise caution and avoid entering sensitive information.
        </p>
      </div>
    </div>
  `;
  document.querySelector('.site-name').after(alertDiv);
}

// Button handlers
document.getElementById("yes-btn").addEventListener("click", () => {
  console.log("Yes button clicked");
  console.log("Continuing to:", originalUrl);
  
  // Additional confirmation for high-risk sites
  if (riskScore > 70) {
    const confirmed = confirm(
      "⚠️ FINAL WARNING ⚠️\n\n" +
      "This site is HIGHLY DANGEROUS!\n" +
      "Risk Score: " + riskScore + "/100\n\n" +
      "Are you ABSOLUTELY SURE you want to continue?\n\n" +
      "Click OK only if you understand the risks."
    );
    
    if (!confirmed) {
      return;
    }
  }
  
  if (!originalUrl || originalUrl === "") {
    console.error("Original URL is empty!");
    alert("Error: No URL to navigate to");
    return;
  }
  
  chrome.runtime.sendMessage({ 
    action: "continue", 
    url: originalUrl
  }, (response) => {
    console.log("Message sent, response:", response);
  });
});

document.getElementById("no-btn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ 
    action: "cancel"
  });
});