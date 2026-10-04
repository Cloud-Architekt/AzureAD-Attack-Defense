# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities in this repository privately. Do not open a public issue, discussion, or pull request, and do not include proof-of-concept code, credentials, tokens, tenant data, customer data, or other sensitive information in a public location.

Use GitHub’s **Private Vulnerability Reporting** feature for this repository:

1. Open the repository’s **Security** tab.
2. Select **Report a vulnerability**.
3. Provide a clear description, affected file or content, impact, reproduction steps, and any safe remediation suggestion.

If the reporting option is unavailable, do not disclose the details publicly. Contact a repository maintainer through a verified contact method on their GitHub profile and request a private reporting channel.

Maintainers: enable GitHub Private Vulnerability Reporting in the repository’s security settings so that the reporting path above is available to reporters.

## Supported content

Security reports are in scope when they concern repository-maintained content that could create a material security risk for users, including:

- Detection queries, rule templates, workbooks, scripts, configuration examples, and deployment artifacts.
- Documentation or instructions that could cause insecure configuration, unintended privileged access, exposure of secrets, or unsafe operational behavior when followed as written.
- Accidental inclusion of credentials, access tokens, tenant identifiers, customer data, or other sensitive information.
- Third-party content or dependencies included in the repository where a known vulnerability affects the supplied artifact.

The playbook is documentation and defensive guidance, not a hosted service or a supported Microsoft product. Product vulnerabilities in Microsoft Entra ID, Azure, Microsoft Defender, Microsoft Sentinel, GitHub, or another third-party service are out of scope for this repository and should be reported to the relevant vendor. Broken external links, editorial corrections, and general feature requests should be opened as ordinary issues unless they create a material security risk.

## What to expect

Maintainers will aim to acknowledge a private report within 14 days, assess its impact, and coordinate a remedy or disclosure plan where appropriate. Please allow reasonable time for review and remediation before public disclosure.
