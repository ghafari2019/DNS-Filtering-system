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

1. **Create VMs for Flask, dnsmasq, Prometheus, and Grafana**.

2. **Set Up Firewall Rules**:
    ```bash
    gcloud compute firewall-rules create allow-flask --allow tcp:5000 --source-ranges 0.0.0.0/0
    gcloud compute firewall-rules create allow-dnsmasq --allow udp:53,tcp:53 --source-ranges 0.0.0.0/0
    gcloud compute firewall-rules create allow-prometheus --allow tcp:9090 --source-ranges 0.0.0.0/0
    gcloud compute firewall-rules create allow-grafana --allow tcp:3000 --source-ranges 0.0.0.0/0
    ```

3. **SSH into Flask VM**

4. Clone the repository:
    ```sh
    git clone https://github.com/ghafari2019/DNS-Filtering-system.git
    cd DNS-Filtering-system
    ```


5. **Create and activate a virtual environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  
    ```

6. **Install the required packages**:
    ```bash
    pip install -r flask_app_requirements.txt
    ```

7. **Check if the pre-trained XGBoost model file (`best_xgboost_model.joblib`) in the directory**:
    ```bash
    ls
    ```

### Step 3: Setup Flask Application

1. **Feature Extraction File (`feature_extraction.py`)**:
```python
import numpy as np
from urllib.parse import urlparse
import ipaddress
import tldextract

def count_chars(url, char):
    return url.count(char)

def count_non_alphanumeric(url):
    return len([char for char in url if not char.isalnum()])

def count_digits(url):
    return len([char for char in url if char.isdigit()])

def count_letters(url):
    return len([char for char in url if char.isalpha()])

def count_params(url):
    return len(urlparse(url).query.split('&')) if urlparse(url).query else 0

def has_php(url):
    return 1 if 'php' in url else 0

def has_html(url):
    return 1 if 'html' in url else 0

def has_at_symbol(url):
    return 1 if '@' in url else 0

def has_double_slash(url):
    return 1 if '//' in urlparse(url).path else 0

def has_http(url):
    return 1 if urlparse(url).scheme == 'http' else 0

def has_https(url):
    return 1 if urlparse(url).scheme == 'https' else 0

def secure_http(url):
    return int(urlparse(url).scheme == 'https')

def have_ip_address(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.hostname:
            ip = ipaddress.ip_address(parsed_url.hostname)
            return isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
    except ValueError:
        pass  # Invalid hostname or IP address
    return 0

def extract_root_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

def has_subdomain(url):
    domain_parts = urlparse(url).hostname.split('.')
    return 1 if len(domain_parts) > 2 else 0

def extract_features(url):
    return np.array([[
        hash(extract_root_domain(url)) % (10 ** 8),  # root_domain as hashed integer
        has_subdomain(url),  # Has_subdomain
        count_chars(url, '.'),  # Count_dots
        count_chars(url, '-'),  # Count_dashes
        count_chars(url, '_'),  # Count_underscores
        count_chars(url, '/'),  # Count_slashes
        count_chars(url, '?'),  # Count_ques
        count_non_alphanumeric(url),  # Count_non_alphanumeric
        count_digits(url),  # Count_digits
        count_letters(url),  # Count_letters
        count_params(url),  # Count_params
        has_php(url),  # Has_php
        has_html(url),  # Has_html
        has_at_symbol(url),  # Has_at_symbol
        has_http(url),  # Has_http
        have_ip_address(url),  # have_ip
        has_https(url)  # HTTPS_token
    ]], dtype=float)  # Ensure all features are float
```

2. **Create Flask Application (`app_gc.py`)**:
```python
import os
from flask import Flask, request, jsonify
from prometheus_client import Counter, start_http_server, generate_latest  # Added for Prometheus integration
import joblib
from feature_extraction import extract_features  # Import the feature extraction function

app = Flask(__name__)

# Load the pre-trained XGBoost model
model = joblib.load('best_xgboost_model.joblib')

# Initialize Prometheus metrics
MALICIOUS_URL_COUNTER = Counter('malicious_url_counter_total', 'Count of Malicious URLs Detected')  # Added for Prometheus metric

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    url = data['url']

    # Extract features
    features = extract_features(url)  # Call the feature extraction function

    # Predict using the model
    prediction = model.predict(features)
    result = {'malicious': bool(prediction)}

    # Increment the Prometheus counter if the URL is malicious
    if prediction:
        MALICIOUS_URL_COUNTER.inc()
        # Log the URL
        app.logger.info(f"Malicious URL detected: {url}")

    return jsonify(result)

if __name__ == '__main__':
    # Start Prometheus client HTTP server on port 8000
    start_http_server(8000)
    # Run Flask application
    app.run(host='0.0.0.0', port=5000)
  
```

3. **Run Flask Application**:
    ```bash
    python app.py
    ```
4. **Send a POST request to the `/predict` endpoint with a JSON body containing the URL to be evaluated:**
   Open a new SSH session, navigate to the venv directory, while app_gc.py is still running in the first SSH session, and execute the following command:
    ```sh
    curl -X POST -H "Content-Type: application/json" -d "{\"url\": \"http://example.com\"}" http://localhost:5000/predict
    ```
    *localhost: External vm  instanve IP*


5. **The app will respond with a JSON object indicating whether the URL is malicious:**
    ```json
    {
      "malicious": true
    }
    ```

    

### Step 4: Configure dnsmasq

1. **Install dnsmasq**:
    ```bash
    sudo apt-get install dnsmasq
    ```

2. **Edit Main Configuration File:**
    ```bash
    sudo nano /etc/dnsmasq.conf
    ```
    Ensure it includes:
    ```plaintext
    conf-dir=/etc/dnsmasq.d
    ```

3. **Edit Custom Configuration File:**
    ```bash
    sudo nano /etc/dnsmasq.d/custom.conf
    ```
    Ensure it includes:
    ```plaintext
    addn-hosts=/etc/dnsmasq.d/hosts.blocklist
    ```

4. **Ensure Blocklist File Exists:**
    ```bash
    sudo touch /etc/dnsmasq.d/hosts.blocklist
    ```

5. **Validate Configuration:**
    ```bash
    sudo dnsmasq --test
    ```

6. **Restart Service:**
    ```bash
    sudo systemctl restart dnsmasq
    ```

7. **Check Service Status:**
    ```bash
    sudo systemctl status dnsmasq
    ```

By following these steps, you should be able to correctly configure and restart the `dnsmasq` service. 

  
  
  
  ### Step 5: Create a Script for DNS Queries (`dns_filter.sh`)

1. **Open a text editor to create the script**:
    ```bash
    nano dns_filter.sh
    ```

2. **Add the following script content**:

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

3. **Save and close the file**:
    - If using `nano`, press `Ctrl+X`, then `Y` to confirm changes, and `Enter` to save.

4. **Make the script executable**:
    ```bash
    chmod +x dns_filter.sh
    ```

By following these steps, you will create and configure the `dns_filter.sh` script, making it executable and ready for use in your DNS filtering system.

 
 

### Step 6: Install and Configure Prometheus

1. **Install Prometheus**:
    ```bash
    sudo apt-get update
    sudo apt-get install prometheus
    ```

2. **Open the Prometheus Configuration File**:
    ```bash
    sudo nano /etc/prometheus/prometheus.yml
    ```

3. **Configure Prometheus (`/etc/prometheus/prometheus.yml`)**:
    Add or modify the configuration to include a job for scraping Flask metrics. Insert the following lines under the existing `global` and `scrape_configs` sections:
    ```yaml
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    scrape_configs:
      - job_name: 'flask_metrics'
        static_configs:
          - targets: ['<Flask_VM_IP>:8000']
    ```
    Replace `<Flask_VM_IP>` with the actual IP address of your Flask server.

4. **Save and Close the File**:
    - If using `nano`, press `Ctrl+X` to exit the editor.
    - Press `Y` to confirm the changes.
    - Press `Enter` to save the file with the same name.

5. **Restart Prometheus**:
    ```bash
    sudo systemctl restart prometheus
    ```

6. **Verify Prometheus Status**:
    ```bash
    sudo systemctl status prometheus
    ```

By following these steps, you will install and configure Prometheus to scrape metrics from your Flask application, ensuring that your monitoring setup includes the necessary metrics collection.

### Step 7: Install and Configure Grafana

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
    - Open Grafana at `http://<Grafana_VM_IP>:3000`.
    - Add Prometheus as a data source:
      - Navigate to Configuration > Data Sources > Add Data Source > Prometheus.
      - Set URL to `http://<Prometheus_VM_IP>:9090`.
      - Click "Save & Test".

### Step 7: Create Dashboards and Alerts in Grafana

1. **Create Dashboards**:
    - Open Grafana and create a new dashboard.
    - Add a new panel to visualize the `malicious_url_counter_total` metric.

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
