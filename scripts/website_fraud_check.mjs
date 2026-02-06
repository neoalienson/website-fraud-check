#!/usr/bin/env node

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
        try {
            const url = new URL(urlString);
            const issues = [];

            // Check for IP address in URL
            const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
            if (ipPattern.test(url.hostname)) {
                issues.push(`⚠️  URL uses IP address instead of domain: ${url.hostname}`);
            }

            // Check for URL shorteners
            const shortenerPattern = /(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|lnkd\.in|is\.gd|ow\.ly|bit\.do|adf\.ly|bc\.vc|cur\.lv|ity\.im|v\.gd|tr\.im|cli\.gs|flic\.kr|po\.st|doiop\.com|shorte\.st|u\.bb|vzturl\.com|buff\.ly|wp\.me|fb\.me|bitly\.com|j\.mp|bit\.ws|t2m\.io|link\.zip\.net|rb\.gy|gen\.iu|tiny\.cc|viralstories\.in)/i;
            if (shortenerPattern.test(url.hostname)) {
                issues.push(`⚠️  URL uses URL shortener service: ${url.hostname}`);
            }

            // Check for excessive subdomains (may indicate typo-squatting)
            const subdomainCount = url.hostname.split('.').length - 2;
            if (subdomainCount > 2) {
                issues.push(`⚠️  Excessive subdomains detected: ${subdomainCount} levels`);
            }

            // Check for suspicious patterns in the URL
            for (const pattern of this.suspiciousPatterns) {
                if (pattern.test(url.hostname) || pattern.test(url.pathname) || pattern.test(url.search)) {
                    issues.push(`⚠️  Suspicious pattern detected: ${pattern.toString()}`);
                }
            }

            // Check for homograph attacks (using characters that look similar to Latin letters)
            const nonLatinPattern = /[^\u0000-\u007F]/; // Non-ASCII characters
            if (nonLatinPattern.test(url.hostname)) {
                issues.push(`⚠️  Non-ASCII characters detected in hostname (possible homograph attack)`);
            }

            // Check for too many dots or dashes in the hostname
            const dotCount = (url.hostname.match(/\./g) || []).length;
            const dashCount = (url.hostname.match(/-/g) || []).length;
            if (dotCount > 4 || dashCount > 4) {
                issues.push(`⚠️  Unusual number of dots (${dotCount}) or dashes (${dashCount}) in hostname`);
            }

            // Check for suspicious TLDs (free domains often used in phishing)
            const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.bit'];
            for (const tld of suspiciousTlds) {
                if (url.hostname.endsWith(tld)) {
                    issues.push(`⚠️  Suspicious TLD detected: ${tld}`);
                }
            }

            // Check for multiple domains in URL (typo-squatting)
            const suspiciousCombos = ['google.com.', 'facebook.com.', 'paypal.com.', 'amazon.com.', 'apple.com.'];
            for (const combo of suspiciousCombos) {
                if (url.hostname.includes(combo) && !url.hostname.startsWith(combo.replace('.', ''))) {
                    issues.push(`⚠️  Suspicious domain combination detected: ${combo}`);
                }
            }

            return issues;
        } catch (error) {
            return [`❌ Invalid URL: ${error.message}`];
        }
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
            // NOTE: Order matters! More specific patterns should come before general ones
            const datePatterns = [
                /Creation Date[^\d]*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/i,  // ISO format with timestamp (T and Z) - specific first
                /Updated Date[^\d]*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/i,  // ISO format with timestamp (T and Z) - specific first
                /Registry Expiry Date[^\d]*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/i,  // ISO format with timestamp (T and Z) - specific first
                /created[^\d]*(\d{4}-\d{2}-\d{2})/i,  // General pattern - less specific
                /creation date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // General pattern - less specific
                /created on[^\d]*(\d{4}-\d{2}-\d{2})/i,  // General pattern - less specific
                /create date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // General pattern - less specific
                /register date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // General pattern - less specific
                /registrar registration[^\d]*(\d{4}-\d{2}-\d{2})/i,  // General pattern - less specific
                /Registration Date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Additional pattern for .ai domains - less specific
                /Domain Registration Date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Another common pattern - less specific
                /Created on[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Another variation - less specific
                /Domain Name Commencement Date[^\d]*(\d{2}-\d{2}-\d{4})/i,  // .hk domain format (DD-MM-YYYY)
                /Creation Date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Alternative format - less specific
                /Creation date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Lowercase variant - less specific
                /registrant created[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Some registries use this format - less specific
                /created-date[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Hyphenated format - less specific
                /Registered on[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Capitalized variant - less specific
                /Record created on[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Extended format - less specific
                /Registration Time[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Alternative term - less specific
                /Domain created[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Different phrasing - less specific
                /Domain registered[^\d]*(\d{4}-\d{2}-\d{2})/i,  // Different phrasing - less specific
                /Fecha de registro[^\d]*(\d{2}\/\d{2}\/\d{4})/i,  // Spanish format (DD/MM/YYYY)
                /Date de création[^\d]*(\d{2}\/\d{2}\/\d{4})/i,   // French format (DD/MM/YYYY)
                /登録日[^\d]*(\d{4}-\d{2}-\d{2})/i,             // Japanese format (YYYY-MM-DD)
                /등록일[^\d]*(\d{4}-\d{2}-\d{2})/i,              // Korean format (YYYY-MM-DD)
                /注册时间[^\d]*(\d{4}-\d{2}-\d{2})/i,            // Chinese simplified format (YYYY-MM-DD)
                /註冊時間[^\d]*(\d{4}-\d{2}-\d{2})/i              // Chinese traditional format (YYYY-MM-DD)
            ];

            for (const pattern of datePatterns) {
                const match = result.match(pattern);
                if (match) {
                    let creationDate;
                    // Attempt to parse directly first (ISO, YYYY-MM-DD, etc.)
                    let parsedDate = new Date(match[1]);

                    if (!isNaN(parsedDate.getTime())) {
                        creationDate = parsedDate;
                    } else if (match[1].includes('/')) {
                        // Handle DD/MM/YYYY format
                        const [day, month, year] = match[1].split('/');
                        creationDate = new Date(`${year}-${month}-${day}`);
                    } else if (match[1].includes('-') && match[1].length === 10) {
                        // Handle DD-MM-YYYY format (like .hk domains)
                        // This applies when direct parsing failed and it's a hyphenated 10-char string
                        const [day, month, year] = match[1].split('-');
                        creationDate = new Date(`${year}-${month}-${day}`);
                    } else {
                        // Fallback, though should be covered by direct parsing or specific formats
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
                        resolve({ isValid: false, issuer: null, error: 'Could not retrieve certificate' });
                    } else {
                        resolve({ 
                            isValid: true, 
                            issuer: cert.issuer ? `${cert.issuer.O || 'Unknown'} CA` : 'Unknown', 
                            error: null 
                        });
                    }
                } else {
                    // If we can't get the certificate, the connection may still be valid
                    // but we can't verify the certificate
                    resolve({ isValid: true, issuer: 'Unknown', error: null });
                }
            });

            req.on('error', (err) => {
                resolve({ isValid: false, issuer: null, error: err.message });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({ isValid: false, issuer: null, error: 'Connection timeout' });
            });

            req.end();
        });
    }

    /**
     * Fetch website content with Playwright first (if available), static as fallback
     */
    async fetchWebsiteContent(urlString) {
        let browser = null; // Initialize browser to null
        try {
            const { chromium } = await import('playwright');
            browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
            const page = await browser.newPage();
            
            // Set a realistic user agent
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
            
            // Navigate to the page
            await page.goto(urlString, { waitUntil: 'networkidle', timeout: 15000 });
            
            // Wait for content to load
            await page.waitForLoadState('domcontentloaded', { timeout: 10000 });
            
            // Get the content after JavaScript execution
            const dynamicContent = await page.content();
            
            console.log('   ✅ Content fetched successfully with Playwright (dynamic rendering)');
            
            return {
                statusCode: 200, // Assume success since Playwright loaded the page
                headers: {},
                content: dynamicContent
            };
        } catch (dynamicError) {
            // Playwright failed, warn user about reduced accuracy
            console.log(`   ⚠️  Playwright failed: ${dynamicError.message}`);
            console.log('   ⚠️  Falling back to static content fetching - accuracy may be reduced without dynamic rendering');
            // Do not re-throw here, let the outer function handle the fallback.
        } finally {
            if (browser) {
                await browser.close(); // Ensure browser is always closed
            }
        }

        // Fallback to static content fetching
        try {
            const staticContent = await this.fetchStaticContent(urlString);
            console.log('   ⚠️  Content fetched with static method - some dynamic elements may be missing');
            return staticContent;
        } catch (staticError) {
            console.debug(`Failed to fetch website content: ${staticError.message}`);
            throw staticError;
        }
    }

    /**
     * Fetch website content statically
     */
    async fetchStaticContent(urlString) {
        return new Promise((resolve, reject) => {
            const url = new URL(urlString);
            const options = {
                hostname: url.hostname,
                port: url.port || (url.protocol === 'https:' ? 443 : 80),
                path: url.pathname + url.search,
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; FraudCheckBot/1.0)'
                },
                timeout: 10000
            };

            const protocol = url.protocol === 'https:' ? https : http;
            
            const req = protocol.request(options, (res) => {
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
     * Analyze website content for fraud indicators
     */
    analyzeWebsiteContent(content, hostname) {
        const impersonation = [];
        const fraudIndicators = [];
        const brandMentions = [];

        // Brands that are commonly impersonated
        const targetBrands = [
            'google', 'facebook', 'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 
            'spotify', 'adobe', 'github', 'twitter', 'instagram', 'linkedin', 'yahoo',
            'gmail', 'youtube', 'whatsapp', 'snapchat', 'tiktok', 'discord',
            'paypal', 'hangseng', 'hsbc', 'bochk', 'bankofchina', 'standardchartered', 
            'dbs', 'ocbc', 'citicbank', 'winglung', 'chbank', 'hkbea', 'bankcomm'
        ];

        // Convert content to lowercase for comparison
        const lowerContent = content.toLowerCase();

        // Check for brand mentions
        for (const brand of targetBrands) {
            // Use word boundaries to avoid partial matches
            const regex = new RegExp(`\\b${brand}\\b`, 'gi');
            const matches = content.match(regex) || [];
            
            if (matches.length > 0) {
                // Determine if this is likely impersonation
                const isOfficialDomain = this.legitimateDomains.some(domain => 
                    hostname.includes(domain.toLowerCase()) || domain.toLowerCase().includes(hostname.toLowerCase())
                );
                
                if (!isOfficialDomain) {
                    // Add to impersonation if not on official domain
                    impersonation.push({
                        brand: brand,
                        count: matches.length,
                        confidence: matches.length > 5 ? 'high' : 'medium'
                    });
                }
                
                // Always add to brand mentions for analysis
                brandMentions.push({
                    brand: brand,
                    count: matches.length
                });
            }
        }

        // Look for common fraud indicators in the content
        const fraudPatterns = [
            /urgent/i,
            /immediate action required/i,
            /verify your account/i,
            /confirm your identity/i,
            /security alert/i,
            /suspicious activity/i,
            /locked|lock/i,
            /suspended/i,
            /reactivate/i,
            /update your information/i,
            /personal details/i,
            /credit card/i,
            /ssn|social security/i,
            /password/i,
            /login credentials/i,
            /confirm now/i,
            /act now/i,
            /limited time/i,
            /congratulations.*winner/i,
            /claim your prize/i,
            /free money/i,
            /click here/i,
            /act immediately/i,
            /verify immediately/i
        ];

        for (const pattern of fraudPatterns) {
            const matches = content.match(pattern) || [];
            if (matches.length > 0) {
                fraudIndicators.push({
                    pattern: pattern.toString(),
                    count: matches.length
                });
            }
        }

        return {
            impersonation,
            fraudIndicators,
            brandMentions
        };
    }

    /**
     * Analyze content without fetching (used for testing)
     */
    analyzeContentWithoutFetching(urlString, hostname) {
        try {
            // For this implementation, we'll return an empty result
            // since we're not actually fetching content
            return { impersonation: [], fraudIndicators: [], brandMentions: [] };
        } catch (error) {
            console.debug(`Error in analyzeContentWithoutFetching: ${error.message}`);
            return { impersonation: [], fraudIndicators: [], brandMentions: [] };
        }
    }

    /**
     * Check website against PhishTank database
     */
    async checkPhishTank(domain) {
        try {
            // PhishTank API requires an HTTP POST request to the correct endpoint
            // Endpoint: https://checkurl.phishtank.com/checkurl/
            // Request parameters: url, format (json), app_key (optional)
            // Headers: Descriptive User-Agent required

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
                    'User-Agent': 'WebsiteFraudChecker/1.0 (contact: contact@example.com)'
                } 
            };

            // Make the POST request using Node.js http module
            return new Promise((resolve) => {
                const req = https.request(options, (res) => {
                    let data = '';

                    res.on('data', (chunk) => {
                        data += chunk;
                    });

                    res.on('end', () => {
                        try {
                            // Parse the response
                            const response = JSON.parse(data);

                            // Check if the URL is in the PhishTank database
                            if (response.results && response.results.valid) {
                                // The URL is in the database, check if it's verified as a phishing site
                                if (response.results.in_database && response.results.verified) {
                                    if (response.results.verified == true && response.results.phishy == true) {
                                        resolve({
                                            isBlacklisted: true,
                                            threatsFound: ['PhishTank verified phishing site'],
                                            confidence: 'high'
                                        });
                                    } else {
                                        // The URL is in the database but not verified as phishing
                                        resolve({
                                            isBlacklisted: false,
                                            threatsFound: [],
                                            confidence: 'low'
                                        });
                                    }
                                } else {
                                    // URL not in database or not yet verified
                                    resolve({
                                        isBlacklisted: false,
                                        threatsFound: [],
                                        confidence: 'low'
                                    });
                                }
                            } else {
                                // Unexpected response format
                                resolve({
                                    isBlacklisted: false,
                                    threatsFound: [],
                                    checkUnavailable: true,
                                    message: 'PhishTank check unavailable: Unexpected API response format.',
                                    confidence: 'low'
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
                                checkUnavailable: true,
                                message: `PhishTank check unavailable: Failed to parse response (${parseError.message})`,
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
                        checkUnavailable: true,
                        message: `PhishTank check unavailable: API request failed (${error.message})`,
                        confidence: 'low'
                    });
                });

                req.write(postData);
                req.end();
            });
        } catch (error) {
            console.debug(`Error checking PhishTank: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                checkUnavailable: true,
                message: `PhishTank check unavailable: An unexpected error occurred (${error.message})`,
                confidence: 'low'
            };
        }
    }

    /**
     * Check website against Google Safe Browsing API
     */
    async checkGoogleSafeBrowsing(url) {
        const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
        
        if (!apiKey) {
            return {
                isBlacklisted: false,
                threatsFound: [],
                checkUnavailable: true,
                message: 'Google Safe Browsing check unavailable: API key not provided',
                confidence: 'low'
            };
        }

        try {
            const response = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    client: {
                        clientId: "website-fraud-checker",
                        clientVersion: "1.0"
                    },
                    threatInfo: {
                        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url: url }]
                    }
                })
            });

            if (response.ok) {
                const data = await response.json();
                if (data.matches && data.matches.length > 0) {
                    const threats = data.matches.map(match => match.threatType);
                    return {
                        isBlacklisted: true,
                        threatsFound: threats,
                        confidence: 'high'
                    };
                }
            }

            return {
                isBlacklisted: false,
                threatsFound: [],
                confidence: 'high'
            };
        } catch (error) {
            console.debug(`Error checking Google Safe Browsing: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                checkUnavailable: true,
                message: `Google Safe Browsing check unavailable: An unexpected error occurred (${error.message})`,
                confidence: 'low'
            };
        }
    }

    /**
     * Check website against multiple threat intelligence services
     */
    async checkThreatIntelligence(urlString) {
        try {
            const url = new URL(urlString);
            const domain = url.hostname;

            // Check each service and collect results
            const phishTankResult = await this.checkPhishTank(domain);
            const googleResult = await this.checkGoogleSafeBrowsing(urlString);

            // Aggregate results
            const allThreats = [
                ...phishTankResult.threatsFound,
                ...googleResult.threatsFound
            ];
            
            const isBlacklisted = phishTankResult.isBlacklisted || googleResult.isBlacklisted;

            let statusMessages = [];
            if (phishTankResult.checkUnavailable) {
                statusMessages.push(phishTankResult.message || 'PhishTank check unavailable.');
            }
            if (googleResult.checkUnavailable) {
                statusMessages.push(googleResult.message || 'Google Safe Browsing check unavailable.');
            }
            
            return {
                isBlacklisted,
                threatsFound: allThreats,
                confidence: 'high', // Will adjust confidence dynamically later if needed
                statusMessage: statusMessages.length > 0 ? statusMessages.join(' ') : ''
            };
        } catch (error) {
            console.debug(`Error in threat intelligence check: ${error.message}`);
            return {
                isBlacklisted: false,
                threatsFound: [],
                checkUnavailable: true,
                message: `Threat intelligence check unavailable: An unexpected error occurred (${error.message})`,
                confidence: 'low',
                statusMessage: `Warning: Threat intelligence check failed due to unexpected error (${error.message})`
            };
        }
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
     * Check for common phishing indicators in domain
     */
    checkPhishingIndicators(hostname) {
        const indicators = [];

        // Check for IP address in hostname
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipRegex.test(hostname)) {
            indicators.push('IP address in hostname');
        }

        // Check for suspicious TLDs
        const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.bit'];
        for (const tld of suspiciousTlds) {
            if (hostname.endsWith(tld)) {
                indicators.push(`Suspicious TLD: ${tld}`);
            }
        }

        // Check for character substitution (homoglyphs)
        const homoglyphs = [
            { char: 'а', replacement: 'a' }, // Cyrillic 'а' vs Latin 'a'
            { char: 'о', replacement: 'o' }, // Cyrillic 'о' vs Latin 'o'
            { char: 'е', replacement: 'e' }, // Cyrillic 'е' vs Latin 'e'
            { char: 'р', replacement: 'p' }, // Cyrillic 'р' vs Latin 'p'
            { char: 'с', replacement: 'c' }, // Cyrillic 'с' vs Latin 'c'
            { char: 'х', replacement: 'x' }, // Cyrillic 'х' vs Latin 'x'
        ];

        for (const glyph of homoglyphs) {
            if (hostname.includes(glyph.char)) {
                indicators.push(`Homoglyph detected: '${glyph.char}' looks like '${glyph.replacement}'`);
            }
        }

        // Check for excessive hyphens (often used in typo-squatting)
        const hyphenCount = (hostname.match(/-/g) || []).length;
        if (hyphenCount > 2) {
            indicators.push(`Excessive hyphens (${hyphenCount}) may indicate typo-squatting`);
        }

        // Check for digits that look like letters
        const digitSubstitutions = [
            { char: '0', replacement: 'o' },
            { char: '1', replacement: 'l' },
            { char: '3', replacement: 'e' },
            { char: '5', replacement: 's' },
            { char: '8', replacement: 'b' },
        ];

        for (const sub of digitSubstitutions) {
            // Check if the character exists but the lookalike letter doesn't
            // This suggests intentional substitution
            const originalLetterExists = hostname.includes(sub.replacement);
            const digitExists = hostname.includes(sub.char);
            
            if (digitExists && originalLetterExists) {
                // If both exist, check if they appear in suspicious patterns
                const pattern = new RegExp(`${sub.char}[^a-z]*${sub.replacement}|${sub.replacement}[^a-z]*${sub.char}`, 'i');
                if (pattern.test(hostname)) {
                    indicators.push(`Potential digit-letter substitution: '${sub.char}' and '${sub.replacement}'`);
                }
            }
        }

        return indicators;
    }

    /**
     * Main function to check website risk
     */
    async checkWebsiteRisk(urlString) {
        console.log(`🔍 Analyzing website: ${urlString}`);

        // Normalize the URL
        let normalizedUrl;
        try {
            if (!urlString.startsWith('http')) {
                normalizedUrl = new URL(`https://${urlString}`);
            } else {
                normalizedUrl = new URL(urlString);
            }
        } catch (error) {
            throw new Error(`Invalid URL: ${error.message}`);
        }

        const websiteUrl = normalizedUrl.href;
        const hostname = normalizedUrl.hostname;

        // Initialize risk score
        let riskScore = 0;

        // Step 1: Analyze URL structure
        console.log('\n🔍 Analyzing URL structure...');
        const urlIssues = this.analyzeUrl(websiteUrl);
        if (urlIssues.length > 0) {
            console.log(`   ⚠️  Found ${urlIssues.length} potential issues:`);
            urlIssues.forEach(issue => console.log(`      ${issue}`));
            riskScore += urlIssues.length * 3; // Add 3 points per URL issue
        } else {
            console.log('   ✅ URL appears structurally sound');
        }

        // Step 2: Check domain age
        console.log('\n📅 Checking domain registration age...');
        const domainAge = await this.checkDomainAge(hostname);
        if (domainAge) {
            if (domainAge.isNew) {
                console.log(`   ⚠️  Domain ${domainAge.rootDomain} is relatively new (${domainAge.ageInDays} days old)`);
                riskScore += 10; // New domains get higher risk
            } else {
                console.log(`   ✅ Domain ${domainAge.rootDomain} has been registered for ${domainAge.ageInDays} days`);
            }
        } else {
            console.log('   ℹ️  Could not determine domain age (whois may not be available)');
            riskScore += 5; // Uncertain domain age increases risk slightly
        }

        // Step 3: Check SSL certificate
        console.log('\n🔒 Checking SSL certificate...');
        const sslResult = await this.checkSSL(hostname);
        if (sslResult.isValid) {
            console.log(`   ✅ SSL certificate is valid (issued by: ${sslResult.issuer})`);
        } else {
            console.log(`   ⚠️  SSL certificate issue: ${sslResult.error || 'Invalid certificate'}`);
            riskScore += 15; // Invalid SSL significantly increases risk
        }

        // Step 4: Analyze website content
        console.log('\n📄 Analyzing website content...');
        let contentResult;
        try {
            const fetchedContent = await this.fetchWebsiteContent(websiteUrl); 
            contentResult = this.analyzeWebsiteContent(fetchedContent.content, hostname);
            console.log(`   ✅ Content fetched successfully (${fetchedContent.content.length} chars)`);
            
            if (contentResult.impersonation.length > 0) {
                console.log(`   ⚠️  Found ${contentResult.impersonation.length} potential impersonation indicators:`);
                contentResult.impersonation.forEach(imp => {
                    console.log(`      - Brand name "${imp.brand}" found in content but site is not on official domain (confidence: ${imp.confidence})`);
                });
            }
            
            if (contentResult.fraudIndicators.length > 0) {
                console.log(`   ⚠️  Found ${contentResult.fraudIndicators.length} potential fraud indicators:`);
                contentResult.fraudIndicators.forEach(ind => {
                    console.log(`      - Pattern "${ind.pattern}" found ${ind.count} times`);
                });
                riskScore += contentResult.fraudIndicators.length * 2;
            }
        } catch (error) {
            console.log(`   ⚠️  Could not fetch website content: ${error.message}`);
            console.log('   ℹ️  Proceeding with analysis based on other factors');
            riskScore += 10; // Can't analyze content, increase risk
        }

        // Step 5: Check against threat intelligence feeds
        console.log('\n🛡️  Checking against threat intelligence feeds...');
        const threatResult = await this.checkThreatIntelligence(websiteUrl);
        
        if (threatResult.statusMessage) {
            console.log(`   ⚠️  ${threatResult.statusMessage}`);
            riskScore += 5; // Add a small risk for unavailable checks
        }

        if (threatResult.isBlacklisted) {
            console.log(`   ❌ Site found in threat feeds: ${threatResult.threatsFound.join(', ')}`);
            riskScore += 50; // Blacklisted sites get very high risk
        } else if (!threatResult.statusMessage) { // Only log "Site not found" if no statusMessage (i.e., checks were performed and found nothing)
            console.log('   ✅ Site not found in threat feeds');
        }
        // Step 6: Check for phishing indicators in domain
        const phishingIndicators = this.checkPhishingIndicators(hostname);
        if (phishingIndicators.length > 0) {
            console.log(`   ⚠️  Found ${phishingIndicators.length} phishing indicators in domain:`);
            phishingIndicators.forEach(indicator => console.log(`      - ${indicator}`));
            riskScore += phishingIndicators.length * 5;
        }

        // Step 7: Add points for impersonation indicators with differentiated scoring
        
        // Calculate impersonation score with a cap to prevent unlimited accumulation
        let impersonationScore = 0;
        const MAX_IMPERSONATION_SCORE = 10; // Cap the total points from impersonation indicators
        
        for (const impersonation of contentResult?.impersonation || []) {
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

        // Step 8: Check website popularity to reduce risk for popular sites
        const popularityReduction = await this.checkWebsitePopularity(hostname);
        riskScore = Math.max(0, riskScore - popularityReduction); // Ensure score doesn't go below 0

        // Step 9: Calculate final risk assessment
        console.log('\n📊 Calculating risk assessment...');
        console.log(`   Overall Risk Score: ${riskScore}/100`);

        let riskLevel, riskColor, recommendation;
        if (riskScore <= 14) {
            riskLevel = 'LOW';
            riskColor = '🟢';
            recommendation = 'Appears safe, exercise normal caution';
        } else if (riskScore <= 29) {
            riskLevel = 'MEDIUM';
            riskColor = '🟠';
            recommendation = 'Exercise caution, verify legitimacy';
        } else if (riskScore <= 49) {
            riskLevel = 'HIGH';
            riskColor = '🟡';
            recommendation = 'Exercise extreme caution';
        } else {
            riskLevel = 'CRITICAL';
            riskColor = '🔴';
            recommendation = 'Do not trust, avoid entering information';
        }

        console.log(`   Risk Level: ${riskColor} ${riskLevel}`);
        console.log('\n📋 Recommendations:');
        console.log(`   ${riskColor} ${recommendation}`);

        // Final assessment
        console.log(`\nFinal Assessment: This website is ${riskColor} ${riskLevel} risk for fraud/scam`);

        return {
            url: websiteUrl,
            riskScore,
            riskLevel,
            riskColor,
            recommendations: recommendation,
            details: {
                urlAnalysis: urlIssues,
                domainAge,
                ssl: sslResult,
                contentAnalysis: contentResult || null,
                threatIntelligence: threatResult,
                phishingIndicators,
                popularityImpact: {
                    reduction: popularityReduction,
                    domainChecked: hostname,
                    rootDomain: this.extractRootDomain(hostname)
                }
            }
        };
    }
}

// Export the class for use in other modules
export { WebsiteFraudChecker };

// If this script is run directly, execute the main function
if (import.meta.url === `file://${process.argv[1]}`) {
    async function main() {
        if (process.argv.length < 3) {
            console.log('Usage: node website_fraud_check.mjs <website_url>');
            process.exit(1);
        }

        const url = process.argv[2];
        const checker = new WebsiteFraudChecker();

        // Show threat intelligence service status
        console.log('Threat Intelligence Service Status:');
        console.log('  PhishTank: Active - Basic lookups available without API key');
        if (process.env.GOOGLE_SAFE_BROWSING_API_KEY) {
            console.log('  Google Safe Browsing: Active - API key provided');
        } else {
            console.log('  Google Safe Browsing: Inactive - Missing GOOGLE_SAFE_BROWSING_API_KEY environment variable');
        }
        console.log('');

        try {
            await checker.checkWebsiteRisk(url);
        } catch (error) {
            console.error(`Error analyzing website: ${error.message}`);
            process.exit(1);
        }
    }

    main();
}
