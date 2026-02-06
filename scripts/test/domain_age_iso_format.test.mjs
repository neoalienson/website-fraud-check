import { test, describe, expect, vi, beforeEach } from 'vitest';
import { execSync } from 'child_process';
import { WebsiteFraudChecker } from '../website_fraud_check.mjs';

// Mock the execSync function to prevent actual whois calls
vi.mock('child_process', async () => {
  const actual = await vi.importActual('child_process');
  return {
    ...actual,
    execSync: vi.fn()
  };
});

describe('WebsiteFraudChecker - Domain Age Check with ISO Format Dates', () => {
  let checker;

  beforeEach(() => {
    checker = new WebsiteFraudChecker();
  });

  test('should correctly parse ISO format dates with timestamps from whois results', async () => {
    // Mock the execSync call to return the LIHKG.COM whois result
    vi.mocked(execSync).mockReturnValueOnce(`Domain Name: LIHKG.COM Registry Domain ID: 2074223633_DOMAIN_COM-VRSN Registrar WHOIS Server: whois.namecheap.com Registrar URL: http://www.namecheap.com Updated Date: 2025-10-16T08:01:02Z Creation Date: 2016-11-15T03:23:26Z Registry Expiry Date: 2026-11-15T03:23:26Z Registrar: NameCheap, Inc. Registrar IANA ID: 1068 Registrar Abuse Contact Email: abuse@namecheap.com Registrar Abuse Contact Phone: +1.6613102107 Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited Name Server: KEVIN.NS.CLOUDFLARE.COM Name Server: LEAH.NS.CLOUDFLARE.COM DNSSEC: signedDelegation DNSSEC DS Data: 2371 13 2 58D97E3E1407557951D9AAD4AA0554BF3C45210C7C94765E800C37E6F6C18E45 URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/`);

    const result = await checker.checkDomainAge('lihkg.com');

    expect(result).not.toBeNull();
    expect(result.creationDate).toBe('2016-11-15T03:23:26Z');
    expect(result.ageInDays).toBeGreaterThan(3000); // 3371 days as of now
    expect(result.isNew).toBe(false); 
    expect(result.rootDomain).toBe('lihkg.com');
  });

  test('should correctly parse Creation Date with ISO format', async () => {
    // Mock whois result with Creation Date in ISO format
    vi.mocked(execSync).mockReturnValueOnce(`Domain Name: EXAMPLE.COM
Registrar: Example Registrar
Creation Date: 2020-05-20T10:30:00Z
Updated Date: 2023-01-15T14:22:45Z
Registry Expiry Date: 2024-05-20T10:30:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM`);

    const result = await checker.checkDomainAge('example.com');

    expect(result).not.toBeNull();
    expect(result.creationDate).toBe('2020-05-20T10:30:00Z');
    expect(result.ageInDays).toBeGreaterThan(1000); // More than 1 year old
    expect(result.isNew).toBe(false); 
  });

  test('should correctly parse Updated Date with ISO format', async () => {
    // Mock whois result with Updated Date in ISO format (though we prioritize Creation Date)
    vi.mocked(execSync).mockReturnValueOnce(`Domain Name: TEST.NET
Registrar: Test Registrar
Updated Date: 2023-06-10T08:15:30Z
Creation Date: 2019-02-14T12:00:00Z
Registry Expiry Date: 2024-02-14T12:00:00Z`);

    const result = await checker.checkDomainAge('test.net');

    expect(result).not.toBeNull();
    expect(result.creationDate).toBe('2019-02-14T12:00:00Z'); // Should find Creation Date first
    expect(result.ageInDays).toBeGreaterThan(1500); // More than 1 year old
    expect(result.isNew).toBe(false); 
  });

  test('should correctly parse Registry Expiry Date with ISO format', async () => {
    // Mock whois result where Creation Date is in ISO format
    vi.mocked(execSync).mockReturnValueOnce(`Domain Name: EXPIRY.ORG
Registrar: Expiry Registrar
Registry Expiry Date: 2025-12-31T23:59:59Z
Creation Date: 2018-07-04T09:15:22Z
Updated Date: 2023-07-04T09:15:22Z`);

    const result = await checker.checkDomainAge('expiry.org');

    expect(result).not.toBeNull();
    expect(result.creationDate).toBe('2018-07-04T09:15:22Z'); // Should find Creation Date
    expect(result.ageInDays).toBeGreaterThan(2000); // More than 1 year old
    expect(result.isNew).toBe(false); 
  });

  test('should handle mixed date formats in whois result', async () => {
    // Mock whois result with mixed date formats
    vi.mocked(execSync).mockReturnValueOnce(`Domain Name: MIXED.CO.UK
Registrar: Mixed Registrar
Creation Date: 2021-03-15T16:45:30Z
Updated Date: 2023-03-15
Registry Expiry Date: 2024-03-15T16:45:30Z`);

    const result = await checker.checkDomainAge('mixed.co.uk');

    expect(result).not.toBeNull();
    expect(result.creationDate).toBe('2021-03-15T16:45:30Z'); // Should find the ISO format Creation Date
    expect(result.ageInDays).toBeGreaterThan(500); // More than 1 year old
    expect(result.isNew).toBe(false); 
  });

  test('should still work with traditional date formats', async () => {
    // Mock whois result with traditional date format to ensure we didn't break existing functionality
    vi.mocked(execSync).mockReturnValueOnce(`Domain Name: TRADITIONAL.COM
Registrar: Traditional Registrar
Creation Date: 2022-01-15
Updated Date: 2023-01-15
Registry Expiry Date: 2024-01-15`);

    const result = await checker.checkDomainAge('traditional.com');

    expect(result).not.toBeNull();
    expect(result.creationDate).toBe('2022-01-15'); // Should find the traditional format
    expect(result.ageInDays).toBeGreaterThan(500); // More than 1 year old
    expect(result.isNew).toBe(false); 
  });

  test('should handle .hk domain format as well', async () => {
    // Test that we didn't break the .hk domain support
    vi.mocked(execSync).mockReturnValueOnce(`Domain Name: EXAMPLE.HK
Domain Status: Active
Registrar Name: Example Limited
Domain Name Commencement Date: 15-08-2020
Expiry Date: 15-08-2024
`);

    const result = await checker.checkDomainAge('example.hk');

    expect(result).not.toBeNull();
    expect(result.creationDate).toBe('15-08-2020'); // Should find the .hk format
    expect(result.ageInDays).toBeGreaterThan(1000); // More than 1 year old
    expect(result.isNew).toBe(false); 
  });

  test('should return null when no date is found', async () => {
    // Mock whois result with no recognizable date format
    vi.mocked(execSync).mockReturnValueOnce(`Domain Name: NODATE.COM
Registrar: NoDate Registrar
Name Server: NS1.NODATE.COM
`);

    const result = await checker.checkDomainAge('nodate.com');

    expect(result).toBeNull(); // Should return null when no date is found
  });
});