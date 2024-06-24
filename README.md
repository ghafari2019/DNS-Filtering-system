# DNS-Filtering-system
The primary goal of this project is to set up a DNS filtering and URL classification system using Flask, dnsmasq, and a machine learning model. Additionally, the project aims to monitor the system's performance and availability using Prometheus and Grafana

# URL Feature Extraction and Malicious URL Detection

This repository contains a Flask application that uses a pre-trained XGBoost model to predict whether a given URL is malicious. The app extracts various features from the URL and uses them to make predictions.

## Feature Extraction

The application extracts the following features from a given URL to make predictions:

### URL Structure Features
- **Has Subdomain**: Checks if the URL contains a subdomain.
- **Root Domain**: Extracts the root domain of the URL and hashes it as an integer.

### Character Count Features
- **Count Dots**: Counts the number of dots ('.') in the URL.
- **Count Dashes**: Counts the number of dashes ('-') in the URL.
- **Count Underscores**: Counts the number of underscores ('_') in the URL.
- **Count Slashes**: Counts the number of slashes ('/') in the URL.
- **Count Question Marks**: Counts the number of question marks ('?') in the URL.
- **Count Non-Alphanumeric Characters**: Counts the number of non-alphanumeric characters in the URL.
- **Count Digits**: Counts the number of digits in the URL.
- **Count Letters**: Counts the number of letters in the URL.

### Parameter Count Features
- **Count Parameters**: Counts the number of parameters in the URL query string.

### Presence of Specific Substrings
- **Has PHP**: Checks if the URL contains 'php'.
- **Has HTML**: Checks if the URL contains 'html'.
- **Has At Symbol**: Checks if the URL contains the '@' symbol.
- **Has Double Slash**: Checks if the URL contains a double slash ('//').
- **Has HTTP**: Checks if the URL uses the HTTP scheme.
- **Has HTTPS**: Checks if the URL uses the HTTPS scheme.

### Security Features
- **Have IP Address**: Checks if the URL contains an IP address.


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

## Usage

1. Run the Flask app:
    ```sh
    python app.py
    ```

2. Send a POST request to the `/predict` endpoint with a JSON body containing the URL to be evaluated:
    ```sh
    curl -X POST -H "Content-Type: application/json" -d '{"url": "http://example.com"}' http://localhost:5000/predict
    ```

3. The app will respond with a JSON object indicating whether the URL is malicious:
    ```json
    {
      "malicious": true
    }
    ```

## Code

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
    return len([char for char in url if not char.isalnum()])

def count_digits(url):
    return len([char for char in url if char.isdigit()])

def count_letters(url):
    return len([char for char in url if char.isalpha()])

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




### Additional Notes:
1. **`flask_app_requirements.txt`**: Ensure you have a `flask_app_requirements.txt` file listing all dependencies (e.g., Flask, joblib, numpy, tldextract).
2. **Model File**: The path to the model file (`best_xgboost_model.joblib`) should be adjusted according to your project structure.
3. **Environment Variables**: If you are deploying this to a cloud service, you might need to set environment variables for the port or other configuration.

This `README.md` should provide clear guidance for anyone looking to understand, install, and run your project.

