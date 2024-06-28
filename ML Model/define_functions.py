# Define functions to extract features
# Domain-based Features
def extract_pri_domain(url):
    try:
        res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
        pri_domain = res.parsed_url.netloc
    except Exception:
        pri_domain = None
    return pri_domain

def extract_root_domain(url):
    extracted = tldextract.extract(url)
    root_domain = f"{extracted.domain}.{extracted.suffix}"
    return root_domain

def get_domain_length(url):
    domain = urlparse(url).netloc
    return len(domain)

def has_subdomain(url):
    domain_parts = urlparse(url).netloc.split('.')
    return 1 if len(domain_parts) > 2 else 0

# URL-based Features
def get_url_length(url):
    return len(url)

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

def abnormal_url(url):
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    if netloc:
        netloc = str(netloc)
        match = re.search(netloc, url)
        if match:
            return 1
    return 0

# Protocol-based Features
def has_http(url):
    return 1 if urlparse(url).scheme == 'http' else 0

def has_https(url):
    return 1 if urlparse(url).scheme == 'https' else 0

def secure_http(url):
    return int(urlparse(url).scheme == 'https')

# IP-based Features
def has_ipv4(url):
    ipv4_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    return 1 if ipv4_pattern.search(url) else 0

def have_ip_address(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.hostname:
            ip = ipaddress.ip_address(parsed_url.hostname)
            return isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
    except ValueError:
        pass  # Invalid hostname or IP address
    return 0

# HTML-based Features (Dummy placeholders for now)
def dummy_function(url):
    return 0  # Placeholder for complex features that require external data
