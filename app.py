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
