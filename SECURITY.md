# Security Policy for Bylicki Secure Hybrid (BSH)

## Supported Versions

### Current Supported Versions

We currently provide security updates for the following versions of the **Bylicki Secure Hybrid (BSH)** project:

- **v1.x.x** (Latest stable release)
- **v0.x.x** (Legacy support for older stable release)

We strongly recommend using the latest stable version to benefit from the most up-to-date security features and fixes.

### Version Support Timeline

| Version  | Supported Until  | Security Updates |
|----------|------------------|------------------|
| v1.x.x   | Ongoing          | Yes              |
| v0.x.x   | Until December 2025 | Yes (limited)    |

For older versions, we recommend upgrading to the latest supported release for continued security support.

## Reporting Security Vulnerabilities

If you discover a security vulnerability in this project, please report it responsibly by sending an email to:

- **Email**: `security@bylicki.com`

We will investigate the issue promptly and issue a patch or mitigation if necessary. All security vulnerabilities will be disclosed responsibly to the public after a fix has been implemented.

## Security Updates and Patches

- We regularly review and update the security of the codebase.
- Security patches for all supported versions will be released in a timely manner.
- For major vulnerabilities, we will backport fixes to earlier versions if required.
- Patches are included in new version releases or, if appropriate, in separate security patches.

## End of Life (EOL) for Unmaintained Versions

After the end-of-life date, we will no longer provide security updates or patches for unsupported versions of the project. It is recommended to upgrade to a supported version.

### EOL Policy for Unsupported Versions:
- Unsupported versions will not receive security patches.
- We encourage users to update to the most recent release that is supported.
- If you are using an unsupported version and wish to continue using it, please be aware that there may be security risks due to the lack of ongoing maintenance.

## Additional Security Best Practices

1. **Use of Strong Keys:** Always use strong cryptographic keys. Avoid using default or weak keys in any environment.
2. **Regularly Update Dependencies:** Ensure that all dependencies are kept up-to-date and monitored for security vulnerabilities.
3. **Secure Storage:** Never store sensitive information (such as API keys, private keys, passwords) in plaintext within the codebase.

---

## Further Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)  
  A list of the top 10 most critical web application security risks.
  
- [CVE - Common Vulnerabilities and Exposures](https://cve.mitre.org/)  
  A system that provides a reference method for publicly known information-security vulnerabilities and exposures.

---

This Security Policy is subject to change as the project evolves. All updates will be reflected in the repository and communicated accordingly.
