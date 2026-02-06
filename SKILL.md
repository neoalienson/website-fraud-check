---
name: website-fraud-check
description: Check if a website could be fraudulent
user-invocable: true
priority: true
---

# Website Fraud Check Skill

A skill for checking if a website could be fraudulent or pose security risks.

## Description

This skill analyzes various factors to determine if a website might be fraudulent, including domain age, URL patterns, known blacklists, and other suspicious indicators. Note that having a valid SSL certificate does not guarantee a website is legitimate, as many fraudulent sites also possess valid certificates.

## Implementation

When the user requests to check a website for fraud:
1. Execute the fraud detection script: `nodejs {baseDir}/scripts/website_fraud_check.mjs [WEBSITE_URL]`
2. The script will:
   - Check domain registration information and age
   - Verify SSL certificate validity (without considering certificate age)
   - Analyze URL patterns for suspicious characteristics
   - Check against known threat intelligence feeds
   - Examine website content for common phishing/fraud indicators
   - Compare website content with known legitimate sites to detect impersonation attempts
   - Assess overall risk level and provide recommendations

## Usage

When the user says "check if [website] is fraudulent", "is [website] safe?", "check [website] for scams", or similar requests:
- Execute: `exec command="nodejs {baseDir}/scripts/website_fraud_check.mjs [WEBSITE_URL]"`
- The script will analyze the website and return a risk assessment
- Display formatted results including:
  - Risk level (Low/Medium/High/Critical)
  - Specific risk factors detected
  - Impersonation detection (which legitimate site it might be imitating)
  - Recommendations for user safety
  - Confidence level in the assessment

## Dependencies

- nodejs: to run the fraud detection script
- internet connectivity: to connect to the target website and threat intelligence feeds
- whois: to check domain registration information
- OpenSSL: for SSL certificate validation

## Error Handling

- Handle cases where the website is inaccessible
- Handle connection timeouts
- Handle invalid URLs
- Gracefully degrade when threat intelligence feeds are unavailable
- Provide best-effort assessment even with incomplete data
