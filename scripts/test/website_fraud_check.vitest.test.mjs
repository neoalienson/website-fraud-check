import { test, describe, expect, beforeEach, vi } from 'vitest';
import { WebsiteFraudChecker } from '../website_fraud_check_esm.mjs';

describe('WebsiteFraudChecker', () => {
    let checker;

    beforeEach(() => {
        checker = new WebsiteFraudChecker();
        
        // Mock the execAsync function to prevent actual whois calls
        vi.spyOn(checker, 'checkDomainAge').mockImplementation(async (domain) => {
            // Return a mock result simulating an established domain
            return {
                ageInDays: 1000,
                creationDate: '2023-01-01',
                isNew: false
            };
        });
        
        // Mock SSL check to prevent network calls
        vi.spyOn(checker, 'checkSSL').mockResolvedValue({
            isValid: true,
            issuer: 'Mock CA',
            error: null
        });
        
        // Mock individual threat intelligence checks
        vi.spyOn(checker, 'checkPhishTank').mockResolvedValue({
            isBlacklisted: false,
            threatsFound: [],
            confidence: 'high'
        });
        
        vi.spyOn(checker, 'checkGoogleSafeBrowsing').mockResolvedValue({
            isBlacklisted: false,
            threatsFound: [],
            confidence: 'high'
        });
        
        // Mock the combined threat intelligence check
        vi.spyOn(checker, 'checkThreatIntelligence').mockImplementation(async (domain) => {
            // Simulate the aggregation of results from all threat services
            const phishTankResult = await checker.checkPhishTank(domain);
            const googleResult = await checker.checkGoogleSafeBrowsing(domain);
            
            const allThreats = [];
            let isBlacklisted = false;
            let confidence = 'low';
            
            if (phishTankResult.isBlacklisted) {
                isBlacklisted = true;
                allThreats.push(...phishTankResult.threatsFound);
                confidence = 'high';
            }
            
            if (googleResult.isBlacklisted) {
                isBlacklisted = true;
                allThreats.push(...googleResult.threatsFound);
                confidence = 'high';
            }
            
            // Mock service status
            const serviceStatus = {
                phishTank: { active: true, message: 'Active - Basic lookups available without API key' },
                googleSafeBrowsing: { active: false, message: 'Inactive - Missing GOOGLE_SAFE_BROWSING_API_KEY environment variable' }
            };
            
            return {
                isBlacklisted,
                threatsFound: allThreats,
                confidence,
                serviceStatus
            };
        });
        
        // Mock content fetching to prevent network calls
        vi.spyOn(checker, 'fetchWebsiteContent').mockResolvedValue({
            statusCode: 200,
            headers: {},
            content: '<html><body>Mock content for testing</body></html>'
        });
    });

    test('should detect suspicious patterns in URLs', () => {
        const suspiciousUrls = [
            'https://facebook.fps-hk.band/merchant/bank-confirm/chb/522444241',
            'https://secure-paypal.login.com/',
            'https://hsbc.verify-account.com/',
            'https://bank.update-payment.info/'
        ];

        for (const url of suspiciousUrls) {
            const issues = checker.analyzeUrl(url);
            expect(issues.length).toBeGreaterThan(0);
        }
    });

    test('should identify legitimate domains correctly', () => {
        const legitimateDomains = [
            'https://www.google.com/',
            'https://www.hangseng.com/'
        ];

        for (const url of legitimateDomains) {
            // We can't test domain age without whois, so we'll focus on URL analysis
            const issues = checker.analyzeUrl(url);
            // Legitimate sites shouldn't have many suspicious patterns
            expect(issues.length).toBeLessThan(3);
        }
    });

    test('should detect suspicious keywords in URL', () => {
        const urlWithKeywords = 'https://fake-site.com/bank-confirm/verify-payment';
        const issues = checker.analyzeUrl(urlWithKeywords);
        
        // Should detect suspicious patterns like 'bank', 'confirm', 'verify'
        expect(issues.length).toBeGreaterThan(0);
    });

    test('should identify IP addresses in URLs as suspicious', () => {
        const urlWithIP = 'https://192.168.1.1/login.php';
        const issues = checker.analyzeUrl(urlWithIP);
        
        expect(issues.some(issue => issue.includes('IP address'))).toBe(true);
    });

    test('should identify URL shorteners as suspicious', () => {
        const urlWithShortener = 'https://bit.ly/3abc123';
        const issues = checker.analyzeUrl(urlWithShortener);
        
        expect(issues.some(issue => issue.includes('URL shortener'))).toBe(true);
    });

    test('should properly initialize with suspicious patterns', () => {
        expect(checker.suspiciousPatterns).toBeDefined();
        expect(Array.isArray(checker.suspiciousPatterns)).toBe(true);
        expect(checker.suspiciousPatterns.length).toBeGreaterThan(0);
    });

    test('should properly initialize with legitimate domains', () => {
        expect(checker.legitimateDomains).toBeDefined();
        expect(Array.isArray(checker.legitimateDomains)).toBe(true);
        expect(checker.legitimateDomains.length).toBeGreaterThan(0);
    });

    test('should properly analyze website content for impersonation', () => {
        const mockContent = `
            <html>
                <head><title>Facebook Login</title></head>
                <body>
                    <div>Secure Facebook login page</div>
                    <form>Enter your credentials</form>
                </body>
            </html>
        `;
        
        // Temporarily restore the original function for this test
        const originalAnalyze = checker.analyzeWebsiteContent.bind(checker);
        const result = originalAnalyze(mockContent, 'mybank-security.com');
        
        expect(result).toBeDefined();
        expect(result.impersonation).toBeDefined();
        expect(result.fraudIndicators).toBeDefined();
        expect(result.brandMentions).toBeDefined();
        
        // Should detect Facebook impersonation
        expect(result.brandMentions).toContain('facebook');
        expect(result.impersonation.length).toBeGreaterThan(0);
    });

    test('should not detect impersonation for legitimate domains', () => {
        const mockContent = `
            <html>
                <head><title>Facebook</title></head>
                <body>
                    <div>Welcome to Facebook</div>
                </body>
            </html>
        `;
        
        // Temporarily restore the original function for this test
        const originalAnalyze = checker.analyzeWebsiteContent.bind(checker);
        const result = originalAnalyze(mockContent, 'www.facebook.com');
        
        // For legitimate domains, there should be minimal impersonation concerns
        expect(result.impersonation.length).toBeLessThan(2);
    });

    test('should detect fraud indicators in content', () => {
        const mockContent = `
            <html>
                <body>
                    <div>Urgent: Your account has suspicious activity!</div>
                    <div>Please verify your banking information immediately</div>
                    <form>Secure login</form>
                </body>
            </html>
        `;
        
        // Temporarily restore the original function for this test
        const originalAnalyze = checker.analyzeWebsiteContent.bind(checker);
        const result = originalAnalyze(mockContent, 'some-site.com');
        
        expect(result.fraudIndicators.length).toBeGreaterThan(0);
    });

    test('should aggregate results from multiple threat intelligence services', async () => {
        // Create a new instance without mocks for this test to test the actual aggregation
        const unmockedChecker = new WebsiteFraudChecker();
        
        // Mock only the individual services to simulate different responses
        const mockPhishTank = vi.spyOn(unmockedChecker, 'checkPhishTank').mockResolvedValue({
            isBlacklisted: true,
            threatsFound: ['Verified phishing site in PhishTank database (ID: 12345)'],
            confidence: 'high'
        });
        
        const mockGoogleSafeBrowsing = vi.spyOn(unmockedChecker, 'checkGoogleSafeBrowsing').mockResolvedValue({
            isBlacklisted: false,
            threatsFound: [],
            confidence: 'high'
        });
        
        const result = await unmockedChecker.checkThreatIntelligence('test-domain.com');
        
        // Verify that all services were called
        expect(mockPhishTank).toHaveBeenCalled();
        expect(mockGoogleSafeBrowsing).toHaveBeenCalled();
        
        // Verify that results are properly aggregated
        expect(result.isBlacklisted).toBe(true);
        expect(result.threatsFound).toContain('Verified phishing site in PhishTank database (ID: 12345)');
        expect(result.confidence).toBe('high');
        expect(result.serviceStatus).toBeDefined();
        expect(result.serviceStatus.phishTank).toBeDefined();
        expect(result.serviceStatus.googleSafeBrowsing).toBeDefined();
        
        // Clean up
        mockPhishTank.mockRestore();
        mockGoogleSafeBrowsing.mockRestore();
    });
});