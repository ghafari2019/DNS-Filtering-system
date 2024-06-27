# DNS Filtering System with Machine Learning

## Overview

This DNS filtering system automatically recognizes and handles malicious URLs without requiring manual intervention from employees. The system integrates `dnsmasq`, a Flask application, and machine learning to ensure robust and adaptive protection against harmful content.

## How the System Works

![Flowchart](dns_filtering_last.png)

### DNS Resolution and Filtering

1. **dnsmasq**: Acts as the local DNS server, directing all DNS queries through it.
2. **Flask Application**: Receives DNS queries forwarded by `dnsmasq` and uses a machine learning model to classify URLs.
3. **Classification**: The machine learning model classifies URLs as benign, defacement, phishing, or malware.
4. **Response**: Based on the classification, the system allows or blocks the URL. Malicious URLs are blocked, protecting employees from harmful content.

### Automation and Monitoring

1. **Prometheus**: Collects and monitors metrics from the Flask application and the overall system.
2. **Grafana**: Visualizes these metrics and sets up alerts for specific conditions (e.g., high memory usage, detection of malicious URLs).




## Why Our Method is Better

This setup ensures that employees are protected from malicious URLs automatically, with minimal impact on their workflow. The comprehensive monitoring and alerting system further enhances security and reliability.

### Automation and Intelligence

- **Automatic Classification**: No manual checks are needed; the system handles all URL classifications automatically.
- **Adaptability**: Using a machine learning model, the system continuously adapts and improves its accuracy in detecting malicious URLs.

### Real-Time Monitoring and Alerts

- **Immediate Protection**: Processes and filters DNS queries in real-time, offering immediate protection.
- **Live Metrics and Alerts**: Clients can see live metrics and receive immediate notifications for critical issues.

### Comprehensive Monitoring

1. **Prometheus**: Collects and monitors metrics from the Flask application and the overall system.
2. **Grafana**: Visualizes these metrics and sets up alerts for specific conditions (e.g., high memory usage, detection of malicious URLs).

### Cost-Effective

- **Open-Source Tools**: Utilizes open-source tools, reducing costs while maintaining high effectiveness.


## Comparison with Other Models

### Blacklisting and Whitelisting

- **How It Works**: Blocks access to known malicious sites (blacklist) or allows access only to approved sites (whitelist).
- **Drawbacks**: Requires constant updates and maintenance; can miss new threats or be overly restrictive.

### Signature-Based Filtering

- **How It Works**: Uses known malware signatures to detect and block malicious URLs.
- **Drawbacks**: Ineffective against new, unknown threats; requires frequent updates.

### Heuristic/Behavioral Analysis

- **How It Works**: Analyzes URL behavior to detect anomalies.
- **Drawbacks**: Higher false positive rate; computationally intensive.

### Content Filtering

- **How It Works**: Inspects web page content in real-time.
- **Drawbacks**: High computational load; can impact browsing performance.

### Proxy-Based Filtering

- **How It Works**: Routes traffic through a proxy server that enforces filtering rules.
- **Drawbacks**: Can introduce latency; single point of failure.

## Summary

Our method combines the efficiency of `dnsmasq` for DNS handling and the adaptability of a Flask application with machine learning for intelligent filtering. This approach ensures a smart, automated, real-time, and cost-effective solution for DNS filtering, providing robust protection against a wide range of threats.

 

