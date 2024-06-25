# DNS URL Filtering System

This project sets up a DNS URL filtering system using Flask, dnsmasq, Prometheus, and Grafana. The admin system handles URL checking and blocking, and notifications are sent to both the admin and the employees who attempt to access blocked URLs.

## Overview

1. **Admin System**:
   - Hosts Flask, dnsmasq, Prometheus, and Grafana.
   - Acts as the DNS server for the network.
   - Checks URLs for malicious content and blocks them if necessary.
   - Notifies employees about blocked URLs.
   - Tracks which employee (IP address) attempted to access a blocked URL.

2. **Employee Systems**:
   - Configured to use the admin system as their DNS server.
   - Receive notifications about blocked URLs.

## Setup

### Prerequisites

- Python 3.x
- Virtual environment
- Prometheus
- dnsmasq
- Grafana

### Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/your_project.git
    cd your_project
    ```

2. **Create and Activate a Virtual Environment**:
    ```bash
    python3 -m venv myenv
    source myenv/bin/activate
    ```

3. **Install the Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

### Step 1: Setup Flask Application

1. **Install Flask and Prometheus Client**:
    ```bash
    pip install Flask prometheus_client
    ```

2. **Create Flask Application (app.py)**:
    ```python
    from flask import Flask, request, jsonify
    from prometheus_client import Counter, start_http_server, generate_latest
    import smtplib
    from email.mime.text import MIMEText

    app = Flask(__name__)

    # Define a counter for malicious URLs
    malicious_url_counter = Counter('malicious_url_counter_total', 'Count of Malicious URLs Detected')

    # Email settings
    SMTP_SERVER = 'smtp.example.com'
    SMTP_PORT = 587
    EMAIL_USER = 'your_email@example.com'
    EMAIL_PASS = 'your_password'

    def send_email(to_address, subject, body):
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = to_address

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, [to_address], msg.as_string())

    @app.route('/predict', methods=['POST'])
    def predict():
        data = request.get_json(force=True)
        url = data['url']
        employee_ip = request.remote_addr  # Get employee's IP address

        # URL classification logic
        is_malicious = True  # Dummy condition for example

        if is_malicious:
            malicious_url_counter.inc()  # Increment the counter if URL is malicious
            send_email('admin@example.com', 'Malicious URL Blocked', f'Blocked URL: {url} from IP: {employee_ip}')
            send_email(f'{employee_ip}@example.com', 'URL Blocked Notification', f'The URL {url} has been blocked due to being malicious.')
            return jsonify({'malicious': True})

        return jsonify({'malicious': False})

    @app.route('/metrics', methods=['GET'])
    def metrics():
        return generate_latest(), 200

    if __name__ == '__main__':
        start_http_server(8000)  # Start the Prometheus metrics server
        app.run(host='0.0.0.0', port=5000)
    ```

3. **Run Flask Application Locally**:
    ```bash
    python app.py
    ```

### Step 2: Configure dnsmasq

1. **Install dnsmasq**:
    ```bash
    sudo apt-get install dnsmasq
    ```

2. **Configure dnsmasq (/etc/dnsmasq.conf)**:
    ```conf
    server=127.0.0.1#5000
    port=53
    listen-address=127.0.0.1

    # Log each DNS query
    log-queries

    # Log extra information about DHCP transactions
    log-dhcp

    # Include another lot of configuration options
    conf-dir=/etc/dnsmasq.d
    ```

3. **Create a Script for DNS Queries (dns_filter.sh)**:
    ```bash
    #!/bin/bash

    DOMAIN=$1
    RESPONSE=$(curl -s -X POST http://127.0.0.1:5000/predict -H "Content-Type: application/json" -d '{"url": "'$DOMAIN'"}')
    CLASSIFICATION=$(echo $RESPONSE | jq -r '.malicious')

    if [ "$CLASSIFICATION" == "true" ]; then
        echo "0.0.0.0"
    else
        dig +short $DOMAIN
    fi
    ```

4. **Make the Script Executable**:
    ```bash
    chmod +x /path/to/dns_filter.sh
    ```

5. **Create /etc/dnsmasq.d/custom.conf**:
    ```conf
    addn-hosts=/etc/dnsmasq.d/hosts.blocklist
    ```

6. **Restart dnsmasq**:
    ```bash
    sudo systemctl restart dnsmasq
    ```

### Step 3: Deploy Flask Application with Gunicorn

1. **Install Gunicorn**:
    ```bash
    pip install gunicorn
    ```

2. **Create systemd Service for Gunicorn (/etc/systemd/system/gunicorn.service)**:
    ```ini
    [Unit]
    Description=gunicorn daemon
    After=network.target

    [Service]
    User=ghafari_ghzl
    Group=www-data
    WorkingDirectory=/home/ghafari_ghzl
    ExecStart=/home/ghafari_ghzl/myenv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 app:app

    [Install]
    WantedBy=multi-user.target
    ```

3. **Start and Enable Gunicorn Service**:
    ```bash
    sudo systemctl start gunicorn
    sudo systemctl enable gunicorn
    ```

### Step 4: Install and Configure Prometheus

1. **Install Prometheus**:
    ```bash
    sudo apt-get update
    sudo apt-get install prometheus
    ```

2. **Configure Prometheus (/etc/prometheus/prometheus.yml)**:
    ```yaml
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    scrape_configs:
      - job_name: 'flask_metrics'
        static_configs:
          - targets: ['localhost:8000']
    ```

3. **Restart Prometheus**:
    ```bash
    sudo systemctl restart prometheus
    ```

### Step 5: Install and Configure Grafana

1. **Install Grafana**:
    ```bash
    sudo apt-get install -y grafana
    ```

2. **Start Grafana**:
    ```bash
    sudo systemctl start grafana-server
    sudo systemctl enable grafana-server
    ```

3. **Configure Grafana**:
    - Open Grafana at `http://<your_server_ip>:3000`.
    - Add Prometheus as a data source:
      - Navigate to Configuration > Data Sources > Add Data Source > Prometheus.
      - Set URL to `http://localhost:9090`.
      - Click "Save & Test".

### Step 6: Create Dashboards and Alerts in Grafana

1. **Create Dashboards**:
    - Add a new dashboard.
    - Add panels for monitoring the `malicious_url_counter_total` metric.

2. **Set Up Alerts**:
    - In the panel editor, click on the `Alert` tab.
    - Click on `Create Alert`.
    - Define the alert condition:
      - **Query**: `malicious_url_counter_total`
      - **Condition**: `IS ABOVE 0`
      - **Evaluate every**: `1m`
      - **For**: `5m`
    - Add notification channels (email, Slack, etc.).

### Step 7: Testing and Verification

1. **Simulate Malicious URL Detection**:
    - Send a POST request to the Flask application:
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"url": "http://malicious_url_example.com"}' http://localhost:5000/predict
    ```

2. **Verify Metrics Exposure**:
    - Ensure the metrics are exposed by running:
    ```bash
    curl http://localhost:8000/metrics
    ```

3. **Verify Alerts in Grafana**:
    - Check the Grafana dashboard for updates to the `malicious_url_counter_total` metric.
    - Ensure alerts are triggered and notifications are sent.

### Network Configuration for Employee Systems

1. **Set DNS Server to Admin System**:
   - Configure each employee system to use the admin system's IP as the DNS server.
   - This can usually be done via DHCP settings on the router or manually configuring network settings on each employee system.

## Summary

By following these steps, you can deploy a comprehensive DNS URL filtering system that not only blocks malicious URLs but also notifies both the admin and the individual employee attempting to access
