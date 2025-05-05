# Domain Threat Assessment: Analyzing Malicious Activity with VirusTotal
A hands-on threat assessment using VirusTotal to uncover phishing, malware, and suspicious behavior across three domains.

## Objective
The analysis was conducted to evaluate the security risks posed by these domains, which were flagged during routine threat intelligence monitoring. The goal was to determine their threat level and provide actionable insights for mitigation.

## Tool used
### Tool Configuration

VirusTotal Configuration:
- VirusTotal was accessed via its web interface, “https://www.virustotal.com/gui/home/upload”
- URL Scanning: Submitted each domain to VirusTotal’s URL scanner.
- Threat Intelligence Review: Analyzed domain relationships, including IP resolutions, subdomains, and historical data.
- Sandboxing: Reviewed behavioral reports for dynamic execution analysis.

## Key Findings
- 17ebook.com: Exhibited connections to known malicious IP addresses and was flagged by multiple vendors for phishing.
- aladel.net: Associated with malware distribution and displayed suspicious network behavior, including redirects to blacklisted domains.
- clicnews.com: Identified as a potential C2 server with ties to a known threat actor campaign.

## Recommendations
### Immediate Remediation Actions:
17ebook.com:
- Block all network traffic to and from the IP address.​
- Update security systems to detect and prevent access to known malicious URLs associated with this domain.​

aladel.net:
- Monitor systems for unauthorized modifications to browser extensions and self-launching applications.​
- Implement application whitelisting to prevent execution of untrusted software.​

clicnews.com:
- Maintain vigilance by monitoring network traffic for connections to the IP address​
- Regularly review and update web filtering policies to block access to domains with a history of malicious activity.

### Long-Term Mitigation:
- Threat intelligence updates must run regularly to maintain knowledge about dangerous Internet host domains.​
- Employees require awareness training to understand the dangers associated with unverified web page utilization and phishing.
- The organization should adopt advanced threat detection systems that actively monitor and eliminate potential threats. ​
- Devices with vulnerable ports can be better secured through the enforcement of stringent verification and permissions checks for any attempted access.

[Full Report on Medium](https://medium.com/@folajayeabdulrahman/domain-threat-assessment-analyzing-malicious-activity-with-virustotal-8e98f54c9f62)

