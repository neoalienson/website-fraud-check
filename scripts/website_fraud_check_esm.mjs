import { execSync } from 'child_process';
import https from 'https';
import http from 'http';
import { URL } from 'url';

class WebsiteFraudChecker {
    constructor() {
        // Common suspicious patterns in URLs
        this.suspiciousPatterns = [
            /\.tk(?![a-z])/,         // Free domain providers
            /\.ml(?![a-z])/,         // Free domain providers
            /\.ga(?![a-z])/,         // Free domain providers
            /\.cf(?![a-z])/,         // Free domain providers
            /\.bit(?![a-z])/,        // Free domain providers
            /secure/i,               // Impersonation keywords
            /login/i,
            /account/i,
            /verify/i,
            /confirm/i,
            /update/i,
            /payment/i,
            /bank/i,
            /paypal/i,
            /appleid/i,
            /microsoft/i,
            /google/i,
            /facebook/i,
            /amazon/i,
            /sso/i,                  // Single sign-on impersonation
            /oauth/i,                // OAuth impersonation
            /auth/i,                 // Authentication impersonation
            /signin/i,
            /sign_in/i,
            /log-in/i,
            /log_in/i,
            /www\d*\./,             // Multiple www variations
            /-\w*-\w*-/              // Too many hyphens (typo-squatting)
        ];

        // Load legitimate domains from configuration file
        this.legitimateDomains = this.loadLegitimateDomains();

        // Suspicious keywords that might indicate impersonation
        this.suspiciousKeywords = [
            'secure', 'login', 'account', 'verify', 'confirm', 'update', 'payment',
            'bank', 'paypal', 'appleid', 'microsoft', 'google', 'facebook', 'amazon',
            'sso', 'oauth', 'auth', 'signin', 'sign_in', 'log-in', 'log_in',
            'www', 'customer', 'service', 'support', 'help', 'recovery', 'reset',
            'password', 'forgot', 'change', 'manage', 'access', 'authorize'
        ];

        // Brand names to watch for impersonation
        this.brandNames = [
            'google', 'facebook', 'paypal', 'apple', 'microsoft', 'amazon', 'netflix',
            'spotify', 'adobe', 'github', 'twitter', 'instagram', 'linkedin',
            'youtube', 'gmail', 'outlook', 'hotmail', 'icloud', 'yahoo', 'bing',
            'duckduckgo', 'wikipedia', 'stackoverflow', 'hangseng', 'hsbc', 'bochk',
            'bankofchina', 'standardchartered', 'dbs', 'ocbc', 'citicbank', 'winglung',
            'chbank', 'hkbea', 'bankcomm'
        ];
    }

    /**
     * Load legitimate domains from configuration file
     */
    loadLegitimateDomains() {
        try {
            // Import file system module
            const fs = require('fs');
            const path = require('path');
            
            // Define the path to the legitimate domains file
            const filePath = path.resolve(__dirname, '../config/legitimate-domains.txt');
            
            // Read the file content
            const content = fs.readFileSync(filePath, 'utf8');
            
            // Parse the file content to extract domains
            const domains = content
                .split('\n')
                .map(line => line.trim())
                .filter(line => line && !line.startsWith('#')) // Exclude empty lines and comments
                .filter(line => line.length > 0); // Ensure no empty strings
            
            return domains;
        } catch (error) {
            console.debug(`Could not load legitimate domains from file: ${error.message}`);
            // Return an empty array if the file cannot be loaded
            return [];
        }
    }

    /**
     * Analyze URL for suspicious patterns
     */
    analyzeUrl(urlString) {
        const issues = [];

        // Validate URL format
        try {
            new URL(urlString);
        } catch (e) {
            issues.push('Invalid URL format');
            return issues; // If URL is invalid, return early
        }

        // Check for IP address in URL
        const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
        if (ipRegex.test(urlString)) {
            issues.push('URL contains IP address instead of domain name');
        }

        // Check for URL shorteners
        const shortenerDomains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'rebrand.ly', 'cli.re', 'qr.ae', 'youtu.be'
        ];
        for (const shortener of shortenerDomains) {
            if (urlString.includes(shortener)) {
                issues.push(`URL uses known URL shortener: ${shortener}`);
                break;
            }
        }

        // Check for excessive subdomains (could indicate typo-squatting)
        const subdomainParts = urlString.split('.');
        if (subdomainParts.length > 4) {
            issues.push('Excessive number of subdomains');
        }

        // Check for suspicious patterns in the full URL
        for (const pattern of this.suspiciousPatterns) {
            if (pattern.test(urlString)) {
                issues.push(`Contains suspicious pattern: ${pattern}`);
            }
        }

        // Check for excessive special characters
        const specialCharCount = (urlString.match(/[^a-zA-Z0-9.-]/g) || []).length;
        const ratio = specialCharCount / urlString.length;
        if (ratio > 0.3) {
            issues.push('High proportion of special characters');
        }

        return issues;
    }

    /**
     * Extract the root domain from a hostname, handling subdomains properly
     */
    async checkDomainAge(hostname) {
        try {
            // Extract the root domain from the hostname to check the actual domain age
            const rootDomain = this.extractRootDomain(hostname);
            console.log(`   ℹ️  Checking domain age for root domain: ${rootDomain}`);
            
            // On some systems, whois might not be available or may require sudo
            // We'll handle this gracefully
            const result = execSync(`whois "${rootDomain}"`, { encoding: 'utf8', timeout: 10000 });
            
            // Look for creation/registration date patterns in the whois output
            const datePatterns = [
                /created[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /creation date[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /registration date[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /registered[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /created on[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /create date[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /register date[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /registrar registration[^\d]*(\d{4}-\d{2}-\d{2})/i,
                /Registration Date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Additional pattern for .ai domains
                /Domain Registration Date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Another common pattern
                /Created on[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Another variation
                /Domain Name Commencement Date[^\d]*(\d{2}-\d{2}-\d{4})/i,  // .hk domain format (DD-MM-YYYY)
                /Creation Date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Alternative format
                /Creation date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Lowercase variant
                /registrant created[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Some registries use this format
                /created-date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Hyphenated format
                /Registered on[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Capitalized variant
                /Record created on[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Extended format
                /Registration Time[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Alternative term
                /Domain created[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Different phrasing
                /Domain registered[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Different phrasing
                /Fecha de registro[^\d]*(\d{2}\/\d{2}\/\d{4})/i,  // Spanish format (DD/MM/YYYY)
                /Date de création[^\d]*(\d{2}\/\d{2}\/\d{4})/i,   // French format (DD/MM/YYYY)
                /登録日[^\d]*(\d{4}-\d{2}-\d{2})/i,             // Japanese format (YYYY-MM-DD)
                /등록일[^\d]*(\d{4}-\d{2}-\d{2})/i,              // Korean format (YYYY-MM-DD)
                /注册时间[^\d]*(\d{4}-\d{2}-\d{2})/i,            // Chinese simplified format (YYYY-MM-DD)
                /註冊時間[^\d]*(\d{4}-\d{2}-\d{2})/i             // Chinese traditional format (YYYY-MM-DD)
            ];

            for (const pattern of datePatterns) {
                const match = result.match(pattern);
                if (match) {
                    let creationDate;
                    // Handle different date formats
                    if (match[1].includes('/')) {
                        // Handle DD/MM/YYYY format
                        const [day, month, year] = match[1].split('/');
                        creationDate = new Date(`${year}-${month}-${day}`);
                    } else if (match[1].includes('-') && match[1].length === 10 && parseInt(match[1].substring(0, 2)) > 31) {
                        // Handle YYYY-MM-DD format
                        creationDate = new Date(match[1]);
                    } else if (match[1].includes('-') && match[1].length === 10) {
                        // Handle DD-MM-YYYY format (like .hk domains)
                        const [day, month, year] = match[1].split('-');
                        creationDate = new Date(`${year}-${month}-${day}`);
                    } else {
                        // Default to YYYY-MM-DD format
                        creationDate = new Date(match[1]);
                    }
                    
                    const today = new Date();
                    const diffTime = Math.abs(today - creationDate);
                    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

                    return {
                        ageInDays: diffDays,
                        creationDate: match[1],
                        isNew: diffDays < 365, // Less than 1 year old
                        rootDomain: rootDomain
                    };
                }
            }

            // If no creation date found, return null
            return null;
        } catch (error) {
            // If whois command fails, try alternative methods or return null
            // This could happen if whois is not installed or accessible
            console.debug(`Could not check domain age for ${hostname} (root: ${this.extractRootDomain(hostname)}): ${error.message}`);
            return null;
        }
    }

    /**
     * Check SSL certificate validity
     */
    checkSSL(hostname) {
        return new Promise((resolve) => {
            const options = {
                hostname: hostname,
                port: 443,
                method: 'GET',
                timeout: 5000
            };

            const req = https.request(options, (res) => {
                // The certificate is available in res.connection.getPeerCertificate()
                if (res.connection && typeof res.connection.getPeerCertificate === 'function') {
                    const cert = res.connection.getPeerCertificate();

                    if (Object.keys(cert).length === 0) {
                        resolve({
                            isValid: false,
                            issuer: null,
                            error: 'No certificate presented'
                        });
                    } else {
                        const now = new Date();
                        const validFrom = new Date(cert.valid_from);
                        const validUntil = new Date(cert.valid_to);

                        resolve({
                            isValid: now >= validFrom && now <= validUntil,
                            issuer: cert.issuer.CN || cert.issuer.O,
                            error: now < validFrom ? 'Certificate not yet valid' : 
                                  now > validUntil ? 'Certificate expired' : null
                        });
                    }
                } else {
                    resolve({
                        isValid: false,
                        issuer: null,
                        error: 'Could not retrieve certificate'
                    });
                }

                // End the request to prevent hanging
                res.destroy();
            }).on('error', (err) => {
                resolve({
                    isValid: false,
                    issuer: null,
                    error: err.message
                });
            }).on('timeout', () => {
                req.destroy();
                resolve({
                    isValid: false,
                    issuer: null,
                    error: 'Connection timeout'
                });
            });

            req.end();
        });
    }

    /**
     * Check against known threat intelligence feeds (PhishTank API, Google Safe Browsing API)
     */
    async checkThreatIntelligence(domain) {
        try {
            // Initialize results array to collect findings from all threat feeds
            const allThreats = [];
            let isBlacklisted = false;
            let confidence = 'low';
            const serviceStatus = {
                phishTank: { active: false, message: '' },
                googleSafeBrowsing: { active: false, message: '' }
            };

            // Check PhishTank (doesn't require API key)
            const phishTankResult = await this.checkPhishTank(domain);
            serviceStatus.phishTank.active = true;
            serviceStatus.phishTank.message = 'Active - Basic lookups available without API key';
            if (phishTankResult.isBlacklisted) {
                isBlacklisted = true;
                allThreats.push(...phishTankResult.threatsFound);
                confidence = 'high';
            }

            // Check Google Safe Browsing API (requires API key)
            const googleResult = await this.checkGoogleSafeBrowsing(domain);
            if (process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
                serviceStatus.googleSafeBrowsing.active = true;
                serviceStatus.googleSafeBrowsing.message = 'Active - API key provided';
            } else {
                serviceStatus.googleSafeBrowsing.message = 'Inactive - Missing GOOGLE_SAFE_BROWSING_API_KEY environment variable';
            }
            if (googleResult.isBlacklisted) {
                isBlacklisted = true;
                allThreats.push(...googleResult.threatsFound);
                confidence = 'high';
            }

            // Log service status for transparency
            console.log('Threat Intelligence Service Status:');
            console.log(`  PhishTank: ${serviceStatus.phishTank.message}`);
            console.log(`  Google Safe Browsing: ${serviceStatus.googleSafeBrowsing.message}`);

            return {
                isBlacklisted,
                threatsFound: allThreats,
                confidence,
                serviceStatus  // Include service status in the result
            };
        } catch (error) {
            console.debug(`Threat intelligence check failed: ${error.message}. Using fallback.`);
            // Fallback to phishing indicators check
            return this.checkPhishingIndicators(domain);
        }
    }

    /**
     * Check URL against PhishTank API
     */
    async checkPhishTank(domain) {
        try {
            // PhishTank API requires an HTTP POST request to the correct endpoint
            // Endpoint: https://checkurl.phishtank.com/checkurl/
            // Request parameters: url, format (json), app_key (optional)
            // Headers: Descriptive User-Agent required

            // Prepare the POST request body with URL encoding
            const urlToCheck = `https://${domain}`;
            const postData = `url=${encodeURIComponent(urlToCheck)}&format=json`;

            // Create the HTTPS request options for the correct endpoint
            const options = {
                hostname: 'checkurl.phishtank.com',
                port: 443,  // Note: the endpoint uses HTTPS, not HTTP
                path: '/checkurl/',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': Buffer.byteLength(postData),
                    'User-Agent': 'phishtank/Nekochan'  // Required descriptive User-Agent
                }
            };

            // Make the POST request using Node.js https module
            return new Promise((resolve) => {
                const req = https.request(options, (res) => {
                    let data = '';

                    res.on('data', (chunk) => {
                        data += chunk;
                    });

                    res.on('end', () => {
                        try {
                            const response = JSON.parse(data);

                            // Check if the URL is in PhishTank database
                            if (response && response.results) {
                                // Look for the URL entry in results (format varies by URL)
                                const urlKey = Object.keys(response.results).find(key =>
                                    key.startsWith('url')
                                );

                                if (urlKey && response.results[urlKey]) {
                                    const urlResult = response.results[urlKey];

                                    if (urlResult.in_database && urlResult.valid) {
                                        resolve({
                                            isBlacklisted: true,
                                            threatsFound: [`Verified phishing site in PhishTank database (ID: ${urlResult.phish_id})`],
                                            confidence: 'high'
                                        });
                                    } else {
                                        resolve({
                                            isBlacklisted: false,
                                            threatsFound: [],
                                            confidence: 'high'
                                        });
                                    }
                                } else {
                                    // If URL not found in database
                                    resolve({
                                        isBlacklisted: false,
                                        threatsFound: [],
                                        confidence: 'high'
                                    });
                                }
                            } else {
                                resolve({
                                    isBlacklisted: false,
                                    threatsFound: [],
                                    confidence: 'high'
                                });
                            }
                        } catch (parseError) {
                            console.debug(`Failed to parse PhishTank response: ${parseError.message}`);
                            // Show first 500 characters of response when parsing fails
                            if (data && data.length > 0) {
                                console.debug(`First 500 chars of response: ${data.substring(0, 500)}`);
                            }
                            resolve({
                                isBlacklisted: false,
                                threatsFound: [],
                                confidence: 'low'
                            });
                        }
                    });
                });

                req.on('error', (error) => {
                    console.debug(`PhishTank API request failed: ${error.message}`);
                    resolve({
                        isBlacklisted: false,
                        threatsFound: [],
                        confidence: 'low'
                    });
                });

                // Write the post data and end the request
                req.write(postData);
                req.end();
            });
        } catch (error) {
            console.debug(`PhishTank API check failed: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                confidence: 'low'
            };
        }
    }

    /**
     * Check URL against Google Safe Browsing API
     */
    async checkGoogleSafeBrowsing(domain) {
        try {
            // Google Safe Browsing API requires an API key
            // API endpoint: https://safebrowsing.googleapis.com/v4/threatMatches:find
            // Requires registration at https://developers.google.com/safe-browsing/

            // For this implementation, we'll check for the presence of an API key in environment
            const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

            if (!apiKey) {
                // Without an API key, we cannot make requests to Google Safe Browsing
                return {
                    isBlacklisted: false,
                    threatsFound: [],
                    confidence: 'low'
                };
            }

            const urlToCheck = `https://${domain}`;
            const requestBody = {
                client: {
                    clientId: "website-fraud-check-skill",
                    clientVersion: "1.0.0"
                },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [
                        { url: urlToCheck }
                    ]
                }
            };

            // Create the HTTP request options
            const options = {
                hostname: 'safebrowsing.googleapis.com',
                port: 443,
                path: `/v4/threatMatches:find?key=${apiKey}`,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(JSON.stringify(requestBody))
                }
            };

            return new Promise((resolve) => {
                const req = https.request(options, (res) => {
                    let data = '';

                    res.on('data', (chunk) => {
                        data += chunk;
                    });

                    res.on('end', () => {
                        try {
                            const response = JSON.parse(data);

                            if (response && response.matches && response.matches.length > 0) {
                                // URL is flagged as dangerous
                                const threatTypes = response.matches.map(match => match.threatType);
                                resolve({
                                    isBlacklisted: true,
                                    threatsFound: [`Flagged by Google Safe Browsing as: ${threatTypes.join(', ')}`],
                                    confidence: 'high'
                                });
                            } else {
                                // URL is not in the threat list
                                resolve({
                                    isBlacklisted: false,
                                    threatsFound: [],
                                    confidence: 'high'
                                });
                            }
                        } catch (parseError) {
                            console.debug(`Failed to parse Google Safe Browsing response: ${parseError.message}`);
                            resolve({
                                isBlacklisted: false,
                                threatsFound: [],
                                confidence: 'low'
                            });
                        }
                    });
                });

                req.on('error', (error) => {
                    console.debug(`Google Safe Browsing API request failed: ${error.message}`);
                    resolve({
                        isBlacklisted: false,
                        threatsFound: [],
                        confidence: 'low'
                    });
                });

                // Write the request body and end the request
                req.write(JSON.stringify(requestBody));
                req.end();
            });
        } catch (error) {
            console.debug(`Google Safe Browsing API check failed: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                confidence: 'low'
            };
        }
    }

    /**
     * Analyze website content for impersonation and fraud indicators
     */
    analyzeWebsiteContent(content, hostname) {
        const impersonation = [];
        const fraudIndicators = [];
        const brandMentions = [];

        // Convert content to lowercase for easier searching
        const lowerContent = content.toLowerCase();

        // Look for brand names in the content
        for (const brand of this.brandNames) {
            if (lowerContent.includes(brand.toLowerCase())) {
                brandMentions.push(brand);
                
                // Check if the brand is being impersonated (not on legitimate domain)
                const isLegitimate = this.legitimateDomains.some(domain => 
                    hostname.includes(domain) || domain.includes(hostname)
                );
                
                if (!isLegitimate) {
                    impersonation.push({
                        brand: brand,
                        evidence: `Brand name "${brand}" found in content but site is not on official domain`,
                        confidence: 'high'
                    });
                }
            }
        }

        // Look for suspicious phrases that indicate phishing or fraud
        const suspiciousPhrases = [
            'urgent', 'immediate action required', 'verify your account',
            'confirm your information', 'update your details', 'secure login',
            'suspicious activity', 'unauthorized access', 'locked account',
            'compromised account', 'verify identity', 'confirm identity',
            'enter password', 'login now', 'act now', 'limited time',
            'suspicious login', 'security alert', 'identity verification'
        ];

        for (const phrase of suspiciousPhrases) {
            if (lowerContent.includes(phrase.toLowerCase())) {
                fraudIndicators.push(phrase);
            }
        }

        // Look for form elements that might collect sensitive information
        const sensitiveFormFields = ['password', 'ssn', 'creditcard', 'cvv', 'pin'];
        for (const field of sensitiveFormFields) {
            if (lowerContent.includes(`<input`) && lowerContent.includes(field)) {
                fraudIndicators.push(`Form contains ${field} field`);
            }
        }

        return {
            impersonation,
            fraudIndicators,
            brandMentions
        };
    }

    /**
     * Fetch website content for analysis
     */
    async fetchWebsiteContent(urlString) {
        const url = new URL(urlString);

        return new Promise((resolve, reject) => {
            const protocol = url.protocol === 'https:' ? https : http;
            const requestOptions = {
                hostname: url.hostname,
                port: url.port,
                path: url.pathname + url.search,
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; FraudCheckBot/1.0)'
                },
                timeout: 10000,
                rejectUnauthorized: false
            };

            const req = protocol.request(requestOptions, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        content: data
                    });
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            req.end();
        });
    }

    /**
     * Main function to check website risk
     */
    async checkWebsiteRisk(websiteUrl) {
        console.log(`🔍 Analyzing website: ${websiteUrl}`);
        console.log('');

        // Parse the URL to extract hostname
        let parsedUrl;
        try {
            parsedUrl = new URL(websiteUrl);
        } catch (error) {
            console.error(`❌ Invalid URL: ${error.message}`);
            return;
        }

        const hostname = parsedUrl.hostname;

        // 1. Analyze URL for suspicious patterns
        console.log('🔍 Analyzing URL structure...');
        const urlIssues = this.analyzeUrl(websiteUrl);
        if (urlIssues.length > 0) {
            console.log(`   ❌ Found ${urlIssues.length} potential issues:`);
            for (const issue of urlIssues) {
                console.log(`      - ${issue}`);
            }
        } else {
            console.log(`   ✅ URL appears structurally sound`);
        }
        console.log('');

        // 2. Check domain age
        console.log('📅 Checking domain registration age...');
        const domainAge = await this.checkDomainAge(hostname);
        if (domainAge) {
            if (domainAge.isNew) {
                console.log(`   ⚠️  Domain ${domainAge.rootDomain} is relatively new (${domainAge.ageInDays} days old)`);
            } else {
                console.log(`   ✅ Domain ${domainAge.rootDomain} has been registered for ${domainAge.ageInDays} days`);
            }
        } else {
            console.log(`   ℹ️  Could not determine domain age (whois may not be available)`);
        }
        console.log('');

        // 3. Check SSL certificate
        console.log('🔒 Checking SSL certificate...');
        const sslCheck = await this.checkSSL(hostname);
        if (sslCheck.isValid) {
            console.log(`   ✅ SSL certificate is valid (issued by: ${sslCheck.issuer})`);
        } else {
            console.log(`   ❌ SSL certificate issue: ${sslCheck.error || 'Invalid certificate'}`);
        }
        console.log('');

        // 4. Analyze website content
        console.log('📄 Analyzing website content...');
        try {
            const response = await this.fetchWebsiteContent(websiteUrl);
            if (response.statusCode >= 200 && response.statusCode < 400) {
                console.log(`   ✅ Content fetched successfully (${response.content.length} chars)`);

                const contentAnalysis = this.analyzeWebsiteContent(response.content, hostname);
                if (contentAnalysis.impersonation.length > 0) {
                    console.log(`   ⚠️  Found ${contentAnalysis.impersonation.length} potential impersonation indicators:`);
                    for (const imp of contentAnalysis.impersonation) {
                        console.log(`      - ${imp.evidence} (confidence: ${imp.confidence})`);
                    }
                } else {
                    console.log(`   ✅ No clear impersonation indicators found`);
                }
            } else {
                console.log(`   ❌ Failed to fetch content: Status ${response.statusCode}`);
            }
        } catch (error) {
            console.log(`   ⚠️  Could not fetch content: ${error.message}`);
        }
        console.log('');

        // 5. Check against threat intelligence (simulated)
        console.log('🛡️  Checking against threat intelligence feeds...');
        const threatResult = await this.checkThreatIntelligence(hostname);
        if (threatResult.isBlacklisted) {
            console.log(`   ❌ Site is blacklisted in threat feeds!`);
            console.log(`   Threats found: ${threatResult.threatsFound.join(', ')}`);
        } else {
            console.log(`   ✅ Site not found in threat feeds`);
        }
        console.log('');

        // 6. Calculate risk score
        console.log('📊 Calculating risk assessment...');
        let riskScore = 0;

        // Add points for URL issues
        riskScore += urlIssues.length * 10;

        // Add points for new domain
        if (domainAge && domainAge.isNew) {
            riskScore += 20;
        }

        // Add points for SSL issues
        if (!sslCheck.isValid) {
            riskScore += 15;
        }

        // Add points for impersonation indicators with differentiated scoring
        const contentAnalysis = await this.analyzeContentWithoutFetching(websiteUrl, hostname).catch(() => ({ impersonation: [] }));
        
        // Calculate impersonation score with a cap to prevent unlimited accumulation
        let impersonationScore = 0;
        const MAX_IMPERSONATION_SCORE = 10; // Cap the total points from impersonation indicators
        
        for (const impersonation of contentAnalysis.impersonation) {
            const brand = impersonation.brand.toLowerCase();
            
            // Higher risk for banking/financial brands
            const bankBrands = ['paypal', 'hangseng', 'hsbc', 'bochk', 'bankofchina', 'standardchartered', 
                               'dbs', 'ocbc', 'citicbank', 'winglung', 'chbank', 'hkbea', 'bankcomm'];
            
            if (bankBrands.includes(brand)) {
                impersonationScore += 10; // 10 points for banking brands
            } else {
                impersonationScore += 5;  // 5 points for other tech brands
            }
            
            // Check if we've reached the cap
            if (impersonationScore >= MAX_IMPERSONATION_SCORE) {
                impersonationScore = MAX_IMPERSONATION_SCORE;
                break; // Stop processing additional impersonations once cap is reached
            }
        }
        
        // Add the capped impersonation score to the total risk score
        riskScore += impersonationScore;

        // Check website popularity to reduce risk for popular sites
        const popularityReduction = await this.checkWebsitePopularity(hostname);
        riskScore = Math.max(0, riskScore - popularityReduction); // Ensure score doesn't go below 0

        // Add points if blacklisted
        if (threatResult.isBlacklisted) {
            riskScore += 50;
        }

        // Determine risk level
        let riskLevel;
        let riskColor;
        if (riskScore < 15) {
            riskLevel = 'LOW';
            riskColor = '🟢';
        } else if (riskScore < 30) {
            riskLevel = 'MEDIUM';
            riskColor = '🟠';
        } else if (riskScore < 50) {
            riskLevel = 'HIGH';
            riskColor = '🟡';
        } else {
            riskLevel = 'CRITICAL';
            riskColor = '🔴';
        }

        console.log(`   Overall Risk Score: ${riskScore}/100`);
        console.log(`   Risk Level: ${riskColor} ${riskLevel}`);
        console.log('');

        // 7. Provide recommendations
        console.log('📋 Recommendations:');
        if (riskScore < 15) {
            console.log(`   ✅ Appears safe, exercise normal caution`);
        } else if (riskScore < 30) {
            console.log(`   ⚠️  Exercise caution. Double-check the website before entering sensitive information.`);
            console.log(`   🔍 Verify this is a legitimate new site before providing any information.`);
        } else if (riskScore < 50) {
            console.log(`   ⚠️  Exercise extreme caution. Verify authenticity before proceeding.`);
            console.log(`   ❌ Avoid entering any sensitive information until legitimacy is confirmed.`);
        } else {
            console.log(`   ❌ Do not trust this site. Avoid entering any information.`);
            console.log(`   🔴 Highly likely to be fraudulent or malicious.`);
        }
        console.log('');

        // Final assessment
        console.log(`Final Assessment: This website is ${riskColor} ${riskLevel} risk for fraud/scam`);

        return {
            url: websiteUrl,
            riskScore,
            riskLevel,
            issues: {
                urlIssues,
                domainAge,
                sslCheck,
                threatResult
            }
        };
    }

    /**
     * Helper function to analyze content without fetching (used for error handling)
     */
    async analyzeContentWithoutFetching(websiteUrl, hostname) {
        // This is a helper to avoid fetching content when there are other issues
        // In a real implementation, we'd fetch the content as needed
        try {
            const response = await this.fetchWebsiteContent(websiteUrl);
            if (response.statusCode >= 200 && response.statusCode < 400) {
                return this.analyzeWebsiteContent(response.content, hostname);
            }
        } catch (error) {
            console.debug(`Could not fetch content for analysis: ${error.message}`);
        }
        return { impersonation: [], fraudIndicators: [], brandMentions: [] };
    }

    /**
     * Extract the root domain from a hostname, handling subdomains and multi-part TLDs properly
     */
    extractRootDomain(hostname) {
        // Split the hostname into parts
        const parts = hostname.split('.');

        // Handle multi-part TLDs like .co.uk, .com.au, etc.
        // Common multi-part TLDs
        const multiPartTlds = [
            'co.uk', 'com.au', 'co.jp', 'com.br', 'co.za', 'com.sg', 'com.mx',
            'ne.jp', 'or.jp', 'go.jp', 'ac.jp', 'co.kr', 'co.nz', 'co.za',
            'com.tw', 'com.hk', 'com.ar', 'com.pe', 'com.uy', 'com.py',
            'com.bo', 'com.ec', 'com.gt', 'com.hn', 'com.ni', 'com.pa',
            'com.py', 'com.sv', 'com.ve', 'co.in', 'co.ls', 'co.ma',
            'co.mu', 'co.ke', 'co.cr', 'co.id', 'co.il', 'co.zm',
            'com.af', 'com.ag', 'com.ai', 'com.bn', 'com.bz', 'com.cn',
            'com.do', 'com.dm', 'com.eg', 'com.et', 'com.fj', 'com.gh',
            'com.gi', 'com.gt', 'com.gu', 'com.iq', 'com.jm', 'com.kh',
            'com.kw', 'com.lb', 'com.ly', 'com.mm', 'com.mt', 'com.mx',
            'com.my', 'com.na', 'com.ng', 'com.nf', 'com.om', 'com.pg',
            'com.ph', 'com.pk', 'com.pr', 'com.py', 'com.qa', 'com.sa',
            'com.sb', 'com.sg', 'com.sl', 'com.sv', 'com.tj', 'com.tt',
            'com.tw', 'com.ua', 'com.uy', 'com.vc', 'com.ve', 'com.vn'
        ];

        // If the last two parts form a known multi-part TLD, take the last three parts
        if (parts.length >= 3) {
            const lastTwoParts = parts.slice(-2).join('.');
            if (multiPartTlds.includes(lastTwoParts)) {
                // For multi-part TLDs, only remove the first part if it's a common subdomain
                if (parts.length > 3) {
                    const commonSubdomains = ['www', 'mail', 'ftp', 'blog', 'shop', 'api', 'dev', 'test', 'docs', 'support', 'admin', 'secure'];
                    if (commonSubdomains.includes(parts[0].toLowerCase())) {
                        return parts.slice(-3).join('.'); // Return last 3 parts (subdomain.domain.tld)
                    }
                }
                return parts.slice(-3).join('.'); // Return last 3 parts for multi-part TLDs
            }
        }

        // For regular domains, handle common subdomains properly
        // The logic should remove only the FIRST part if it's a common subdomain
        if (parts.length > 2) {
            const commonSubdomains = ['www', 'mail', 'ftp', 'blog', 'shop', 'api', 'dev', 'test', 'docs', 'support', 'admin', 'secure'];
            
            // Only check if the first part is a common subdomain
            if (commonSubdomains.includes(parts[0].toLowerCase())) {
                // Remove just the first common subdomain, keep the rest
                // e.g., 'api.subdomain.site.net' -> 'subdomain.site.net'
                return parts.slice(1).join('.'); 
            } else {
                // If the first part is not a common subdomain, take the last two parts
                // e.g., 'docs.openclaw.ai' -> 'openclaw.ai'
                return parts.slice(-2).join('.');
            }
        }

        // If it's already a root domain (like 'openclaw.ai'), return as is
        return hostname;
    }

    /**
     * Check website popularity using Tranco list to reduce risk for popular sites
     */
    async checkWebsitePopularity(hostname) {
        try {
            console.log('🌐 Checking website popularity...');
            
            // Check both the full hostname and the root domain
            const rootDomain = this.extractRootDomain(hostname);
            let bestReduction = 0;
            let foundPopularDomain = null;
            
            // First check the full hostname
            const hostReduction = await this.getPopularityReduction(hostname);
            if (hostReduction > bestReduction) {
                bestReduction = hostReduction;
                foundPopularDomain = hostname;
            }
            
            // Then check the root domain if it's different from the hostname
            if (rootDomain !== hostname) {
                const domainReduction = await this.getPopularityReduction(rootDomain);
                if (domainReduction > bestReduction) {
                    bestReduction = domainReduction;
                    foundPopularDomain = rootDomain;
                }
            }
            
            if (foundPopularDomain && bestReduction > 0) {
                console.log(`   ✅ Popular domain found: ${foundPopularDomain} (applied ${bestReduction} point risk reduction)`);
            } else if (!foundPopularDomain) {
                console.log('   ℹ️  Neither hostname nor root domain found in Tranco popularity list');
            }
            
            return bestReduction;
        } catch (error) {
            console.debug(`Error checking website popularity: ${error.message}`);
            return 0; // Return 0 reduction if there's an error
        }
    }

    /**
     * Get popularity reduction for a specific domain
     */
    async getPopularityReduction(domain) {
        try {
            const rankResponse = await fetch(`https://tranco-list.eu/api/ranks/domain/${domain}`);
            if (!rankResponse.ok) {
                if (rankResponse.status === 404) {
                    // Domain not found in Tranco list
                    return 0;
                } else {
                    console.debug(`Could not check Tranco rank for ${domain}: ${rankResponse.status}`);
                    return 0;
                }
            }
            
            const rankData = await rankResponse.json();
            if (rankData.ranks && rankData.ranks.length > 0) {
                // Get the most recent rank
                const latestRank = rankData.ranks[0];
                if (latestRank && latestRank.rank) {
                    const rank = latestRank.rank;
                    
                    // Apply risk reduction based on popularity
                    // As of today, being in top 1,000,000 is considered popular and gets 20 point deduction
                    if (rank <= 1000000) {
                        return 20; // Popular sites get 20 point reduction
                    }
                }
            }
            
            return 0;
        } catch (error) {
            console.debug(`Error checking popularity for ${domain}: ${error.message}`);
            return 0;
        }
    }

    /**
     * Helper function to check for common phishing indicators in domain
     */
    checkPhishingIndicators(domain) {
        // Fallback: check for common phishing indicators
        const phishingIndicators = [
            'secure-login', 'verify-account', 'update-information',
            'confirm-details', 'banking-alert', 'suspicious-login'
        ];

        // Check if domain contains common phishing indicators
        const hasPhishingIndicators = phishingIndicators.some(indicator =>
            domain.toLowerCase().includes(indicator)
        );

        if (hasPhishingIndicators) {
            return {
                isBlacklisted: true,
                threatsFound: ['Domain contains common phishing indicators'],
                confidence: 'medium'
            };
        }

        return {
            isBlacklisted: false,
            threatsFound: [],
            confidence: 'high'
        };
    }
}

export { WebsiteFraudChecker };