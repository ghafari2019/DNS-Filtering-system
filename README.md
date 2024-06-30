# DNS URL Filtering System for Local Network

This project sets up a DNS URL filtering system using Flask, dnsmasq, Prometheus, and Grafana for a local network environment. The system is designed to detect and block malicious URLs, notifying both the administrator and the employees attempting to access these URLs. This solution integrates machine learning for URL classification, providing a robust and adaptive protection mechanism against harmful content.

For instructions on deploying this system on Google Cloud Platform (GCP), please refer to the appropriate documentation in the `google_cloud_setup` directory.

## Setup

### Prerequisites

- Python 3.x
- Virtual environment
- Flask
- dnsmasq
- Gunicorn
- Prometheus
- Grafana

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/ghafari2019/DNS-Filtering-system.git
    cd DNS-Filtering-system
    ```

2. Create and activate a virtual environment:
    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r flask_app_requirements.txt
    ```

4. Place the pre-trained XGBoost model file (`best_xgboost_model.joblib`) in the appropriate directory:
    ```sh
    mkdir -p /home/ghafari_ghzl/
    mv path/to/best_xgboost_model.joblib /home/ghafari_ghzl/
    ```

### Step 1: Setup Flask Application

1. **Install Flask and Prometheus Client:**
    ```bash
    pip install Flask prometheus_client
    ```

2. **Create Flask Application (app.py):**

    ```python
    import os
    from flask import Flask, request, jsonify
    import joblib
    import numpy as np
    from urllib.parse import urlparse
    import ipaddress
    import tldextract

    app = Flask(__name__)

    # Load the pre-trained XGBoost model
    model = joblib.load('/home/ghafari_ghzl/best_xgboost_model.joblib')

    def count_chars(url, char):
        return url.count(char)

    def count_non_alphanumeric(url):
        return len([char for char in url if not char isalnum()])

    def count_digits(url):
        return len([char for char in url if char isdigit()])

    def count_letters(url):
        return len([char for char in url if char isalpha()])

    def count_params(url):
        return len(urlparse(url).query.split('&'))

    def has_php(url):
        return 1 if 'php' in url else 0

    def has_html(url):
        return 1 if 'html' in url else 0

    def has_at_symbol(url):
        return 1 if '@' in url else 0

    def has_double_slash(url):
        return 1 if '//' in url else 0

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
        domain_parts = urlparse(url).netloc.split('.')
        return 1 if len(domain_parts) > 2 else 0

    @app.route('/predict', methods=['POST'])
    def predict():
        data = request.get_json(force=True)
        url = data['url']

        # Extract features
        features = np.array([[
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

        # Predict using the model
        prediction = model.predict(features)
        result = {'malicious': bool(prediction)}

        return jsonify(result)

    if __name__ == '__main__':
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port)
    ```

3. **Run the Flask app:**
    ```sh
    python app.py
    ```

4. **Send a POST request to the `/predict` endpoint with a JSON body containing the URL to be evaluated:**
    ```sh
    curl -X POST -H "Content-Type: application/json" -d '{"url": "http://example.com"}' http://localhost:5000/predict
    ```

5. **The app will respond with a JSON object indicating whether the URL is malicious:**
    ```json
    {
      "malicious": true
    }
    ```

### Step 2: Configure dnsmasq

1. **Install dnsmasq:**
    ```bash
    sudo apt-get install dnsmasq
    ```

2. **Configure `dnsmasq`:**
    - Add the following lines to `/etc/dnsmasq.conf`:
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

3. **Create a Script for DNS Queries (`dns_filter.sh`):**
    ```bash
    #!/bin/bash

    DOMAIN=$1
    RESPONSE=$(curl -s -X POST http://34.80.4.242:5000/classify -H "Content-Type: application/json" -d '{"url": "'$DOMAIN'"}')
    CLASSIFICATION=$(echo $RESPONSE | jq -r '.classification')

    if [ "$CLASSIFICATION" == "malicious" ]; then
        echo "0.0.0.0"
    else
        dig +short $DOMAIN
    fi
    ```

4. **Make the Script Executable:**
    ```bash
    chmod +x dns_filter.sh
    ```

5. **Create `/etc/dnsmasq.d/custom.conf`:**
    ```conf
    addn-hosts=/etc/dnsmasq.d/hosts.blocklist
    ```

    - **Purpose of `hosts.blocklist`**: It contains a predefined list of domains to block.
    - **Dynamic Updating**: You would need an additional script or process to add newly identified malicious URLs to this `hosts.blocklist` file and then reload `dnsmasq` to apply the changes.

6. **Restart dnsmasq:**
    ```bash
    sudo systemctl restart dnsmasq
    ```

### Step 3: Deploy Flask Application with Gunicorn

1. **Install Gunicorn:**
    ```bash
    pip install gunicorn
    ```

2. **Create systemd Service for Gunicorn (`/etc/systemd/system/gunicorn.service`):**
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

3. **Start and Enable Gunicorn Service:**
    ```bash
    sudo systemctl start gunicorn
    sudo systemctl enable gunicorn
    ```

### Step 4: Install and Configure Prometheus

1. **Install Prometheus:**
    ```bash
    sudo apt-get update
    sudo apt-get install prometheus
    ```

2. **Configure Prometheus (`/etc/prometheus/prometheus.yml`):**
    ```yaml
    global:
      scrape_interval: 15s  # Set the scrape interval to every 15 seconds. Default is every 1 minute.
      evaluation_interval: 15s  # Evaluate rules every 15 seconds. The default is every 1 minute.
      # scrape_timeout is set to the global default (10s).

    # Alertmanager configuration
    alerting:
      alertmanagers:
      - static_configs:
        - targets:
          - 'localhost:9093'

    # Load rules once and periodically evaluate them according to the global 'evaluation_interval'.
    rule_files:
      - "alert.rules"

    # A scrape configuration containing exactly one endpoint to scrape:
    # Here it's Prometheus itself.
    scrape_configs:
      - job_name: 'prometheus'
        static_configs:
          - targets: ['localhost:9090']

      # The job for scraping the node exporter
      - job_name: 'node_exporter'
        static_configs:
          - targets: ['34.80.4.242:9100']
    ```

3. **Restart Prometheus:**
    ```bash
    sudo systemctl restart prometheus
    ```

### Step 5: Install and Configure Grafana

1. **Install Grafana:**
    ```bash
    sudo apt-get install -y grafana
    ```

2. **Start Grafana:**
    ```bash
    sudo systemctl start grafana-server
    sudo systemctl enable grafana-server
    ```

3. **Configure Grafana:**
    - Open Grafana at `http://<your_server_ip>:3000`.
    - Add Prometheus as a data source:
        - Navigate to Configuration > Data Sources > Add Data Source > Prometheus.
        - Set URL to `http://localhost:9090`.
        - Click "Save & Test".

### Step 6: Create Dashboards and Alerts in Grafana

1. **Create Dashboards:**
    - Add a new dashboard.
    - Add panels for monitoring the `malicious_url_counter` metric.

2. **Example PromQL Queries:**
    - **Malicious URL Counter:**
      ```promql
      malicious_url_counter
      ```

3. **Set Up Alerts:**
    - Configure alert rules in Grafana to notify when `malicious_url_counter` exceeds a threshold.
    - Configure notification channels (email, Slack, etc.) in Grafana.

### Step 7: Network Configuration for Employee Systems

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

### Step 8: Testing and Verification

1. **Simulate Malicious URL Detection:**
    - Send a POST request to the Flask application:
      ```bash
      curl -X POST -H "Content-Type: application/json" -d '{"url": "http://malicious_url_example.com"}' http://34.80.4.242:5000/classify
      ```

2. **Verify Alerts in Grafana:**
    - Check the Grafana dashboard for updates to the `malicious_url_counter` metric.
    - Ensure alerts are triggered and notifications are sent.

## Usage

- The Flask application will be available on `127.0.0.1:5000`.
- Prometheus will scrape metrics from the Flask application on `localhost:8000`.
- Grafana can be used to visualize the metrics.

### Additional Notes:

1. **`flask_app_requirements.txt`**: Ensure you have a `flask_app_requirements.txt` file listing all dependencies (e.g., Flask, joblib, numpy, tldextract).
2. **Model File**: The path to the model file (`best_xgboost_model.joblib`) should be adjusted according to your project structure.
3. **Environment Variables**: If you are deploying this to a cloud service, you might need to set environment variables for the port or other configuration.

This `README.md` should provide clear guidance for anyone looking to understand, install, and run your project in a local network environment.
