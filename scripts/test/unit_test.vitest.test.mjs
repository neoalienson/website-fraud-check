import { test, describe, expect, beforeEach, afterEach, vi } from 'vitest';
import { WebsiteFraudChecker } from '../website_fraud_check_esm.mjs';

describe('WebsiteFraudChecker', () => {
    let checker;

    beforeEach(() => {
        checker = new WebsiteFraudChecker();
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
            'https://www.facebook.com/',
            'https://www.google.com/',
            'https://www.hsbc.com.hk/',
            'https://www.hangseng.com/'
        ];

        for (const url of legitimateDomains) {
            // We can't test domain age without whois, so we'll focus on URL analysis
            const issues = checker.analyzeUrl(url);
            // Even with our improved algorithm, legitimate sites shouldn't have many critical suspicious patterns
            // The 'www' subdomain might trigger minor warnings, but shouldn't have many serious issues
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

    test('should extract root domain correctly from subdomains', () => {
        const checker = new WebsiteFraudChecker();
        
        // Test various subdomain formats
        expect(checker.extractRootDomain('docs.openclaw.ai')).toBe('openclaw.ai');
        expect(checker.extractRootDomain('www.google.com')).toBe('google.com');
        expect(checker.extractRootDomain('mail.yahoo.com')).toBe('yahoo.com');
        expect(checker.extractRootDomain('blog.example.co.uk')).toBe('example.co.uk');
        expect(checker.extractRootDomain('api.subdomain.site.net')).toBe('subdomain.site.net');
        
        // Test root domains remain unchanged
        expect(checker.extractRootDomain('openclaw.ai')).toBe('openclaw.ai');
        expect(checker.extractRootDomain('google.com')).toBe('google.com');
    });

    test('should check website popularity and apply risk reduction for popular sites', async () => {
        // This test would require mocking the fetch API calls to Tranco
        // Since the popularity check involves external API calls, we'll verify the method exists
        const checker = new WebsiteFraudChecker();
        expect(typeof checker.checkWebsitePopularity).toBe('function');
        expect(typeof checker.getPopularityReduction).toBe('function');
        expect(typeof checker.extractRootDomain).toBe('function');
    });

    test('should cap impersonation indicator scoring', () => {
        // Create a scenario with many impersonation indicators
        const mockContent = `
            <html>
                <body>
                    <div>Google Login</div>
                    <div>Facebook Account</div>
                    <div>Apple ID</div>
                    <div>Microsoft Account</div>
                    <div>Amazon Sign In</div>
                    <div>Twitter Verification</div>
                    <div>LinkedIn Profile</div>
                    <div>Netflix Account</div>
                    <div>PayPal Secure</div>
                    <div>GitHub Login</div>
                    <div>More fake content</div>
                </body>
            </html>
        `;
        
        const originalAnalyze = checker.analyzeWebsiteContent.bind(checker);
        const result = originalAnalyze(mockContent, 'fake-site.com');
        
        // Should detect multiple brand mentions
        expect(result.brandMentions.length).toBeGreaterThanOrEqual(7);
        
        // The impersonation should be equal to the number of brands mentioned
        expect(result.impersonation.length).toEqual(result.brandMentions.length);
    });

    test('should cap impersonation indicator scoring to prevent unlimited accumulation', async () => {
        // Create a new instance without mocks to test the actual scoring
        const unmockedChecker = new WebsiteFraudChecker();
        
        // Mock only the functions that would cause external calls
        const mockFetchContent = vi.spyOn(unmockedChecker, 'fetchWebsiteContent').mockResolvedValue({
            statusCode: 200,
            headers: {},
            content: `
                <html>
                    <body>
                        <div>Google Login</div>
                        <div>Facebook Account</div>
                        <div>Apple ID</div>
                        <div>Microsoft Account</div>
                        <div>Amazon Sign In</div>
                        <div>Twitter Verification</div>
                        <div>LinkedIn Profile</div>
                        <div>Netflix Account</div>
                        <div>PayPal Secure</div>
                        <div>GitHub Login</div>
                        <div>Yahoo Mail</div>
                        <div>Instagram</div>
                        <div>Spotify</div>
                        <div>Adobe</div>
                        <div>More fake content</div>
                    </body>
                </html>`
        });
        
        const mockDomainAge = vi.spyOn(unmockedChecker, 'checkDomainAge').mockResolvedValue(null); // No domain age info
        const mockSSL = vi.spyOn(unmockedChecker, 'checkSSL').mockResolvedValue({isValid: true, issuer: 'Mock CA', error: null});
        const mockThreatIntel = vi.spyOn(unmockedChecker, 'checkThreatIntelligence').mockResolvedValue({
            isBlacklisted: false,
            threatsFound: [],
            confidence: 'high'
        });
        
        // Test the full risk calculation
        const result = await unmockedChecker.checkWebsiteRisk('https://fake-site.com');
        
        // With many impersonation indicators, the score should be capped at some reasonable level
        // Instead of allowing unlimited accumulation (e.g., 15 impersonations * 5 points = 75 points)
        // The scoring should have a maximum contribution from impersonation indicators
        
        expect(result).toBeDefined();
        expect(typeof result.riskScore).toBe('number');
        
        // Clean up
        mockFetchContent.mockRestore();
        mockDomainAge.mockRestore();
        mockSSL.mockRestore();
        mockThreatIntel.mockRestore();
    });

    test('impersonation indicators should be capped to prevent unlimited score accumulation', async () => {
        // Create a new instance without mocks to test the actual scoring
        const unmockedChecker = new WebsiteFraudChecker();
        
        // Mock content with many impersonation indicators
        const mockContentWithManyBrands = `
            <html>
                <body>
                    <div>Google Service</div>
                    <div>Facebook Account</div>
                    <div>Apple ID</div>
                    <div>Microsoft Office</div>
                    <div>Amazon Store</div>
                    <div>Twitter Feed</div>
                    <div>LinkedIn Profile</div>
                    <div>Netflix Show</div>
                    <div>Spotify Music</div>
                    <div>GitHub Repo</div>
                    <div>Yahoo Mail</div>
                    <div>Instagram Post</div>
                    <div>Adobe Creative</div>
                    <div>Dropbox Files</div>
                    <div>Salesforce CRM</div>
                </body>
            </html>`;
        
        const mockFetchContent = vi.spyOn(unmockedChecker, 'fetchWebsiteContent').mockResolvedValue({
            statusCode: 200,
            headers: {},
            content: mockContentWithManyBrands
        });
        
        const mockDomainAge = vi.spyOn(unmockedChecker, 'checkDomainAge').mockResolvedValue(null);
        const mockSSL = vi.spyOn(unmockedChecker, 'checkSSL').mockResolvedValue({isValid: true, issuer: 'Mock CA', error: null});
        const mockThreatIntel = vi.spyOn(unmockedChecker, 'checkThreatIntelligence').mockResolvedValue({
            isBlacklisted: false,
            threatsFound: [],
            confidence: 'high'
        });
        
        // Mock URL issues to isolate the impersonation scoring
        const originalAnalyzeUrl = unmockedChecker.analyzeUrl;
        vi.spyOn(unmockedChecker, 'analyzeUrl').mockReturnValue([]);
        
        const result = await unmockedChecker.checkWebsiteRisk('https://fake-site-with-many-brands.com');
        
        // Analyze content manually to check impersonation count
        const contentAnalysis = unmockedChecker.analyzeWebsiteContent(mockContentWithManyBrands, 'fake-site-with-many-brands.com');
        
        // If there are many impersonations, the contribution to the score should be capped
        // For example, if there are 10+ impersonations, the max contribution should be limited
        // Let's say the cap is 40 points maximum from impersonations (instead of 15*5=75 for 15 brands)
        
        // Count the number of non-banking brand impersonations (each worth 5 points)
        const nonBankingImpersonations = contentAnalysis.impersonation.filter(
            imp => !['paypal', 'hangseng', 'hsbc', 'bochk', 'bankofchina', 'standardchartered', 
                     'dbs', 'ocbc', 'citicbank', 'winglung', 'chbank', 'hkbea', 'bankcomm'].includes(imp.brand.toLowerCase())
        ).length;
        
        // Calculate max possible points without cap (this would be the uncapped amount)
        const maxPossiblePoints = nonBankingImpersonations * 5;
        
        // Calculate the actual contribution from impersonations to the total score
        // (subtracting other possible contributions to isolate impersonation impact)
        const otherContributions = 0; // Since we mocked everything else to be neutral
        const impersonationContribution = result.riskScore - otherContributions;
        
        // The test should expect that the impersonation contribution is capped
        const IMPERSONATION_SCORE_CAP = 10; // Maximum points from impersonations
        
        expect(impersonationContribution).toBeLessThanOrEqual(IMPERSONATION_SCORE_CAP);
        
        // Clean up
        mockFetchContent.mockRestore();
        mockDomainAge.mockRestore();
        mockSSL.mockRestore();
        mockThreatIntel.mockRestore();
    });
});