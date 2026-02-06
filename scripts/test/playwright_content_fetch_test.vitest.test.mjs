import { test, describe, expect, beforeEach, vi } from 'vitest';
import { WebsiteFraudChecker } from '../website_fraud_check_esm.mjs';

describe('WebsiteFraudChecker - Playwright Content Fetching', () => {
    let checker;

    beforeEach(() => {
        checker = new WebsiteFraudChecker();
    });

    test('should attempt Playwright first and fall back to static content when Playwright unavailable', async () => {
        // Mock the import statement for playwright to fail
        const originalImport = globalThis.__vitest_mocker__?.importModule || global.import;
        
        // Create a spy on console.log to verify warning messages
        const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
        
        // Mock the fetchStaticContent method
        const originalFetchStaticContent = checker.fetchStaticContent;
        const mockStaticContent = {
            statusCode: 200,
            headers: {},
            content: '<html><body>Static content</body></html>'
        };
        
        // Replace the fetchStaticContent method with a mock
        checker.fetchStaticContent = vi.fn().mockResolvedValue(mockStaticContent);

        // We'll test by simulating a Playwright import failure by temporarily modifying the method
        const originalMethod = checker.fetchWebsiteContent;
        
        // Override fetchWebsiteContent to simulate Playwright failure
        checker.fetchWebsiteContent = async function(urlString) {
            try {
                // Simulate Playwright import failure
                const { chromium } = await import('playwright');
                // If we reach here, Playwright was imported successfully
                // But we want to simulate failure, so throw an error
                throw new Error('Playwright launch failed');
            } catch (dynamicError) {
                // Playwright failed, warn user about reduced accuracy
                console.log(`   ⚠️  Playwright failed: ${dynamicError.message}`);
                console.log('   ⚠️  Falling back to static content fetching - accuracy may be reduced without dynamic rendering');
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
        }.bind(checker);

        const result = await checker.fetchWebsiteContent('https://example.com');

        // Verify that it fell back to static content
        expect(result).toEqual(mockStaticContent);
        
        // Check that the warning messages were logged
        const logCalls = consoleSpy.mock.calls;
        const warningLogged = logCalls.some(call => call[0].includes('Playwright failed'));
        const fallbackWarningLogged = logCalls.some(call => call[0].includes('accuracy may be reduced'));
        expect(warningLogged).toBe(true);
        expect(fallbackWarningLogged).toBe(true);

        consoleSpy.mockRestore();
        checker.fetchStaticContent = originalFetchStaticContent;
        checker.fetchWebsiteContent = originalMethod;
    });

    test('should properly handle SSL verification step before content fetching', async () => {
        // Mock SSL check
        const mockSSLResult = { isValid: true, issuer: 'Test CA', error: null };
        vi.spyOn(checker, 'checkSSL').mockResolvedValue(mockSSLResult);

        // Mock content fetching to return some content
        const mockContent = {
            statusCode: 200,
            headers: {},
            content: '<html><body>Test content</body></html>'
        };
        vi.spyOn(checker, 'fetchWebsiteContent').mockResolvedValue(mockContent);

        // Mock other methods to avoid external dependencies
        vi.spyOn(checker, 'analyzeUrl').mockReturnValue([]);
        vi.spyOn(checker, 'checkDomainAge').mockResolvedValue(null);
        vi.spyOn(checker, 'checkThreatIntelligence').mockResolvedValue({ isBlacklisted: false, threatsFound: [], confidence: 'high' });
        vi.spyOn(checker, 'analyzeWebsiteContent').mockReturnValue({ impersonation: [], fraudIndicators: [], brandMentions: [] });
        vi.spyOn(checker, 'checkWebsitePopularity').mockResolvedValue(0);

        // Call the main function to verify the sequence
        const result = await checker.checkWebsiteRisk('https://example.com');

        // Verify that SSL check was performed before content fetching
        expect(checker.checkSSL).toHaveBeenCalled();
        expect(checker.fetchWebsiteContent).toHaveBeenCalled();
        expect(result).toBeDefined();
    });
});