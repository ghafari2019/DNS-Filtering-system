# DNS URL Filtering System on Google Cloud Platform (GCP)

This project sets up a DNS URL filtering system using Flask, dnsmasq, Prometheus, and Grafana on Google Cloud Platform. The admin system handles URL checking and blocking, and notifications are sent to both the admin and the employees who attempt to access blocked URLs.

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

- Google Cloud Account
- gcloud CLI installed and configured
- Python 3.x
- Virtual environment
- Prometheus
- dnsmasq
- Grafana

### Step 1: Set Up Google Cloud Environment

1. **Create a Google Cloud Project**:
    ```bash
    gcloud projects create your-project-id
    gcloud config set project your-project-id
    ```

2. **Set Up Billing**:
    - Link a billing account to your project via the Google Cloud Console.

3. **Enable Necessary APIs**:
    ```bash
    gcloud services enable compute.googleapis.com
    gcloud services enable container.googleapis.com
    ```

### Step 2: Create Virtual Machines

1. **Create VMs for Flask, dnsmasq, Prometheus, and Grafana**:
    ```bash
    gcloud compute instances create flask-vm --zone=us-central1-a --machine-type=e2-medium --image-family=debian-10 --image-project=debian-cloud
    gcloud compute instances create dnsmasq-vm --zone=us-central1-a --machine-type=e2-medium --image-family=debian-10 --image-project=debian-cloud
    gcloud compute instances create prometheus-vm --zone=us-central1-a --machine-type=e2-medium --image-family=debian-10 --image-project=debian-cloud
    gcloud compute instances create grafana-vm --zone=us-central1-a --machine-type=e2-medium --image-family=debian-10 --image-project=debian-cloud
    ```

2. **Set Up Firewall Rules**:
    ```bash
    gcloud compute firewall-rules create allow-flask --allow tcp:5000 --source-ranges 0.0.0.0/0
    gcloud compute firewall-rules create allow-dnsmasq --allow udp:53,tcp:53 --source-ranges 0.0.0.0/0
    gcloud compute firewall-rules create allow-prometheus --allow tcp:9090 --source-ranges 0.0.0.0/0
    gcloud compute firewall-rules create allow-grafana --allow tcp:3000 --source-ranges 0.0.0.0/0
    ```

### Step 3: Setup Flask Application

1. **SSH into Flask VM**:
    ```bash
    gcloud compute ssh flask-vm --zone=us-central1-a
    ```

2. **Install Dependencies**:
    ```bash
    sudo apt-get update
    sudo apt-get install python3 python3-venv python3-pip
    pip install Flask prometheus_client gunicorn
    ```

3. **Create Flask Application (app.py)**:
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

4. **Run Flask Application**:
    ```bash
    python app.py
    ```

### Step 4: Configure dnsmasq

1. **SSH into dnsmasq VM**:
    ```bash
    gcloud compute ssh dnsmasq-vm --zone=us-central1-a
    ```

2. **Install dnsmasq**:
    ```bash
    sudo apt-get install dnsmasq
    ```

3. **Configure dnsmasq (/etc/dnsmasq.conf)**:
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

4. **Create a Script for DNS Queries (dns_filter.sh)**:
    ```bash
    #!/bin/bash

    DOMAIN=$1
    RESPONSE=$(curl -s -X POST http://<Flask_VM_IP>:5000/predict -H "Content-Type: application/json" -d '{"url": "'$DOMAIN'"}')
    CLASSIFICATION=$(echo $RESPONSE | jq -r '.malicious')

    if [ "$CLASSIFICATION" == "true" ]; then
        echo "0.0.0.0"
    else
        dig +short $DOMAIN
    fi
    ```

5. **Make the Script Executable**:
    ```bash
    chmod +x /path/to/dns_filter.sh
    ```

6. **Create /etc/dnsmasq.d/custom.conf**:
    ```conf
    addn-hosts=/etc/dnsmasq.d/hosts.blocklist
    ```

7. **Restart dnsmasq**:
    ```bash
    sudo systemctl restart dnsmasq
    ```

### Step 5: Deploy Prometheus

1. **SSH into Prometheus VM**:
    ```bash
    gcloud compute ssh prometheus-vm --zone=us-central1-a
    ```

2. **Install Prometheus**:
    ```bash
    sudo apt-get update
    sudo apt-get install prometheus
    ```

3. **Configure Prometheus (/etc/prometheus/prometheus.yml)**:
    ```yaml
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    scrape_configs:
      - job_name: 'flask_metrics'
        static_configs:
          - targets: ['<Flask_VM_IP>:8000']
    ```

4. **Restart Prometheus**:
    ```bash
    sudo systemctl restart prometheus
    ```

### Step 6: Deploy Grafana

1. **SSH into Grafana VM**:
    ```bash
    gcloud compute ssh grafana-vm --zone=us-central1-a
    ```

2. **Install Grafana**:
    ```bash
    sudo apt-get install -y grafana
    ```

3. **Start Grafana**:
    ```bash
    sudo systemctl start grafana-server
    sudo systemctl enable grafana-server
    ```

4. **Configure Grafana**:
    - Open Grafana at `http://<Grafana_VM_IP>:3000`.
    - Add Prometheus as a data source:
      - Navigate to Configuration > Data Sources > Add Data Source > Prometheus.
      - Set URL to `http://<Prometheus_VM_IP>:9090`.
      - Click "Save & Test".

### Step 7: Create Dashboards and Alerts in Grafana (continued)

2. **Set Up Alerts**:
    - In the panel editor, click on the `Alert` tab.
    - Click on `Create Alert`.
    - Define the alert condition:
      - **Query**: `malicious_url_counter_total`
      - **Condition**: `IS ABOVE 0`
      - **Evaluate every**: `1m`
      - **For**: `5m`
    - Add notification channels (email, Slack, etc.).

### Step 8: Network Configuration for Employee Systems

#### Manual Configuration on Each Device

##### Windows

1. **Open Network Connections**:
   - Press `Windows + R`, type `ncpa.cpl`, and press `Enter`.

2. **Change Adapter Settings**:
   - Right-click on the active network connection (Ethernet/Wi-Fi) and select `Properties`.

3. **Configure IPv4**:
   - Select `Internet Protocol Version 4 (TCP/IPv4)` and click `Properties`.

4. **Set DNS Server Address**:
   - Select `Use the following DNS server addresses`.
   - Enter the cloud-based admin system's IP address in the `Preferred DNS server` field.
   - Click `OK` and `Close`.

##### macOS

1. **Open System Preferences**:
   - Click the Apple menu and select `System Preferences`.

2. **Network Settings**:
   - Click `Network`.

3. **Configure Network Adapter**:
   - Select the active network connection (Wi-Fi/Ethernet) and click `Advanced`.

4. **Set DNS Server Address**:
   - Go to the `DNS` tab.
   - Click the `+` button and add the cloud-based admin system's IP address.
   - Click `OK` and `Apply`.

##### Linux

1. **Edit Network Configuration**:
   - Depending on the Linux distribution and network manager in use, you can edit the network configuration file or use a graphical interface.

2. **Set DNS Server Address**:
   - For example, on Ubuntu with Network Manager, you can use:
     ```bash
     nmcli connection modify <connection_name> ipv4.dns <admin_system_ip>
     nmcli connection up <connection_name>
     ```

#### Automatic Configuration via DHCP Server

1. **Access Router/DHCP Server Settings**:
   - Log in to your router or DHCP server's web interface.

2. **Locate DHCP Settings**:
   - Navigate to the DHCP settings page.

3. **Set DNS Server**:
   - Set the cloud-based admin system's IP address as the primary DNS server.
   - Save the settings and restart the router if necessary.

### Verifying DNS Configuration

To ensure the changes have taken effect, you can check the DNS server settings on the client devices.

#### Windows

1. **Command Prompt**:
   - Open Command Prompt and type:
     ```bash
     ipconfig /all
     ```
   - Verify the DNS Servers list includes the admin system's IP address.

#### macOS

1. **Terminal**:
   - Open Terminal and type:
     ```bash
     scutil --dns
     ```
   - Check the DNS configuration.

#### Linux

1. **Terminal**:
   - Open Terminal and type:
     ```bash
     nmcli dev show | grep DNS
     ```
   - Verify the DNS server.

### Testing and Verification

1. **Simulate Malicious URL Detection**:
   - Send a POST request to the Flask application:
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"url": "http://malicious_url_example.com"}' http://<Flask_VM_IP>:5000/predict
    ```

2. **Verify Metrics Exposure**:
   - Ensure the metrics are exposed by running:
    ```bash
    curl http://<Flask_VM_IP>:8000/metrics
    ```

3. **Verify Alerts in Grafana**:
   - Check the Grafana dashboard for updates to the `malicious_url_counter_total` metric.
   - Ensure alerts are triggered and notifications are sent.

## Summary

By following these steps, you can deploy a comprehensive DNS URL filtering system on Google Cloud Platform (GCP) that not only blocks malicious URLs but also notifies both the admin and the individual employee attempting to access the URL. The system will also track and log the IP address of each employee trying to access a blocked URL.
