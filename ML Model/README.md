# URL Feature Extraction and Classification

This repository contains a script for extracting various features from URLs and preparing the data for machine learning classification. The script includes data loading, feature extraction, data cleaning, visualization, and data splitting for training and testing.

## Table of Contents
- [Requirements](#requirements)
- [Usage](#usage)
- [Code Explanation](#code-explanation)
  - [Importing Libraries](#importing-libraries)
  - [Loading Dataset](#loading-dataset)
  - [Defining Functions for Feature Extraction](#defining-functions-for-feature-extraction)
    - [Domain-based Features](#domain-based-features)
    - [URL-based Features](#url-based-features)
    - [Protocol-based Features](#protocol-based-features)
    - [IP-based Features](#ip-based-features)
    - [HTML-based Features (Dummy Placeholders)](#html-based-features-dummy-placeholders)
  - [Applying Functions to Extract Features](#applying-functions-to-extract-features)
  - [Displaying the DataFrame](#displaying-the-dataframe)
  - [Plotting the Count of Different Types of URLs](#plotting-the-count-of-different-types-of-urls)
  - [Encoding and Labeling](#encoding-and-labeling)
  - [Displaying Value Counts of Root Domain](#displaying-value-counts-of-root-domain)
  - [Applying Hash Encoding and Handling Missing Values](#applying-hash-encoding-and-handling-missing-values)
  - [Removing Constant Features](#removing-constant-features)
  - [Correlation Matrix and Dropping Highly Correlated Features](#correlation-matrix-and-dropping-highly-correlated-features)
  - [Displaying Initial Dataset Info and Handling Missing Values](#displaying-initial-dataset-info-and-handling-missing-values)
  - [Dropping Unnecessary Columns and Splitting Data](#dropping-unnecessary-columns-and-splitting-data)

## Requirements
- Python 3.x
- pandas
- numpy
- seaborn
- matplotlib
- plotly
- scikit-learn
- xgboost
- lightgbm
- catboost
- tldextract
- tld
- colorama
- gensim
- tabulate

Install the required libraries using:
```bash
pip install pandas numpy seaborn matplotlib plotly scikit-learn xgboost lightgbm catboost tldextract tld colorama gensim tabulate
```
## Usage
1. Clone the repository.
2. Ensure you have the required dataset `malicious_phish.csv`.
3. Update the path to the dataset in the script if necessary.
4. Run the script.

## Code Explanation

### Importing Libraries
The script starts by importing all necessary libraries and modules used for data processing, feature extraction, machine learning, visualization, and table formatting.

### Loading Dataset
```python
urls_data = pd.read_csv(r'C:\Users\User\Desktop\cgi interview\malicious_phish.csv')
```
Loads the CSV dataset containing URLs into a pandas DataFrame named `urls_data`.

### Defining Functions for Feature Extraction
This part of the code defines several functions to extract different features from the URLs.

#### Domain-based Features
```python
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
```

These functions extract the primary domain, root domain, length of the domain, and whether the URL has a subdomain.

#### URL-based Features
```python
def get_url_length(url):
    return len(url)

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

def abnormal_url(url):
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    if netloc:
        netloc = str(netloc)
        match = re.search(netloc, url)
        if match:
            return 1
    return 0
```
hese functions extract various characteristics of the URL itself, such as its length, the number of specific characters (e.g., dots, dashes), and whether it contains certain keywords or patterns.

#### Protocol-based Features

```python
def has_http(url):
    return 1 if urlparse(url).scheme == 'http' else 0

def has_https(url):
    return 1 if urlparse(url).scheme == 'https' else 0

def secure_http(url):
    return int(urlparse(url).scheme == 'https')
```
These functions determine whether the URL uses the HTTP or HTTPS protocol and if it is a secure HTTP (HTTPS).

#### IP-based Features
``` python
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
```
These functions check if the URL contains an IPv4 address and if the URL hostname is a valid IP address.
#### HTML-based Features (Dummy Placeholders)


```python
def dummy_function(url):
    return 0  # Placeholder for complex features that require external data
```

## Applying Functions to Extract Features

```python
# Apply functions to extract features
# Domain-based Features
urls_data['pri_domain'] = urls_data['url'].apply(lambda x: extract_pri_domain(str(x)))
urls_data['root_domain'] = urls_data['pri_domain'].apply(lambda x: extract_root_domain(str(x)))
urls_data['Domain_length'] = urls_data['url'].apply(get_domain_length)
urls_data['Has_subdomain'] = urls_data['url'].apply(has_subdomain)

# URL-based Features
urls_data['URL_length'] = urls_data['url'].apply(get_url_length)
urls_data['Count_dots'] = urls_data['url'].apply(lambda x: count_chars(x, '.'))
urls_data['Count_dashes'] = urls_data['url'].apply(lambda x: count_chars(x, '-'))
urls_data['Count_underscores'] = urls_data['url'].apply(lambda x: count_chars(x, '_'))
urls_data['Count_slashes'] = urls_data['url'].apply(lambda x: count_chars(x, '/'))
urls_data['Count_ques'] = urls_data['url'].apply(lambda x: count_chars(x, '?'))
urls_data['Count_non_alphanumeric'] = urls_data['url'].apply(count_non_alphanumeric)
urls_data['Count_digits'] = urls_data['url'].apply(count_digits)
urls_data['Count_letters'] = urls_data['url'].apply(count_letters)
urls_data['Count_params'] = urls_data['url'].apply(count_params)
urls_data['Has_php'] = urls_data['url'].apply(has_php)
urls_data['Has_html'] = urls_data['url'].apply(has_html)
urls_data['Has_at_symbol'] = urls_data['url'].apply(has_at_symbol)
urls_data['Has_double_slash'] = urls_data['url'].apply(has_double_slash)
urls_data['abnormal_url'] = urls_data['url'].apply(lambda x: abnormal_url(x))

# Protocol-based Features
urls_data['Has_http'] = urls_data['url'].apply(has_http)
urls_data['Has_https'] = urls_data['url'].apply(has_https)
urls_data['secure_http'] = urls_data['url'].apply(lambda x: secure_http(x))

# IP-based Features
urls_data['Has_ipv4'] = urls_data['url'].apply(has_ipv4)
urls_data['have_ip'] = urls_data['url'].apply(lambda x: have_ip_address(x))

# HTML-based Features (Dummy placeholders for now)
urls_data['Age_of_Domain'] = urls_data['url'].apply(dummy_function)
urls_data['DNS_record'] = urls_data['url'].apply(dummy_function)
urls_data['PageRank'] = urls_data['url'].apply(dummy_function)
urls_data['Google_Index'] = urls_data['url'].apply(dummy_function)
urls_data['Iframe'] = urls_data['url'].apply(dummy_function)
urls_data['Redirect'] = urls_data['url'].apply(dummy_function)
urls_data['Pop_up_window'] = urls_data['url'].apply(dummy_function)
urls_data['Favicon'] = urls_data['url'].apply(dummy_function)
urls_data['HTTPS_token'] = urls_data['url'].apply(has_https)  # Reuse HTTPS check

```

This section applies the defined functions to extract features from the URLs and adds these features as new columns in the urls_data DataFrame.

## Displaying the DataFrame
```python
print(tabulate(urls_data.head(), headers='keys', tablefmt='psql'))
```

This prints the first few rows of the DataFrame in a formatted table using the **tabulate** library.

## Plotting the Count of Different Types of URLs

```python
count = urls_data['type'].value_counts()
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']
fig = go.Figure(data=[go.Bar(x=count.index, y=count, marker=dict(color=colors))])
fig.update_layout(
    xaxis_title='Types',
    yaxis_title='Count',
    title='Count of Different Types of URLs',
    plot_bgcolor='black',
    paper_bgcolor='black',
    font=dict(color='white')
)
fig.update_xaxes(tickfont=dict(color='white'))
fig.update_yaxes(tickfont=dict(color='white'))
fig.show()
```
This part creates a bar chart to visualize the count of different types of URLs using Plotly.


## Encoding and Labeling
```python
le = LabelEncoder()

# Define a function to hash encode the root_domain
def hash_encode(category):
    hash_object = hashlib.md5(category.encode())
    return int(hash_object.hexdigest(), 16) % (10 ** 8)
```
This section initializes a label encoder and defines a function to hash encode the root domains.

## Displaying Value Counts of Root Domain
```python
# Display the value counts of the root_domain column
print("\nValue counts of 'root_domain' before filtering:")
print(tabulate(urls_data['root_domain'].value_counts().reset_index(), headers=['Root Domain', 'Count'], tablefmt='psql'))

# Filter out rows where root_domain is '0'
urls_data = urls_data[urls_data['root_domain'] != '0']
print("\nValue counts of 'root_domain' after filtering:")
print(tabulate(urls_data['root_domain'].value_counts().reset_index(), headers=['Root Domain', 'Count'], tablefmt='psql'))

# Display the number of unique values in the root_domain column
print("\nNumber of unique root_domain values:", len(urls_data['root_domain'].value_counts()))
```
This part prints the value counts of the root domains before and after filtering out invalid domains.

## Applying Hash Encoding and Handling Missing Values

```python
# Apply the hash encoding function to the root_domain column
urls_data['root_domain'] = urls_data['root_domain'].apply(hash_encode)
urls_data['have_ip'] = urls_data['have_ip'].astype(int)
urls_data['type'] = le.fit_transform(urls_data['type'])

# Display the final DataFrame
print(tabulate(urls_data.head(), headers='keys', tablefmt='psql'))

# Handle missing values efficiently by filling with the median for numeric columns
numeric_columns = urls_data.select_dtypes(include=['int64', 'float64', 'int32', 'int8']).columns
urls_data[numeric_columns] = urls_data[numeric_columns].apply(lambda x: x.fillna(x.median()))
print(numeric_columns)
```

This section applies the hash encoding function to the root domain column, handles missing values, and displays the DataFrame.

## Removing Constant Features
```python
# Remove constant features
constant_features = [column for column in urls_data.columns if urls_data[column].nunique() == 1]
urls_data.drop(columns=constant_features, inplace=True)

# Update numeric columns after dropping constant features
numeric_columns = urls_data.select_dtypes(include=['int64', 'float64', 'int32', 'int8']).columns

# Check for any remaining missing values and fill them if necessary
urls_data[numeric_columns] = urls_data[numeric_columns].fillna(0)
```
This part removes features with constant values and updates the numeric columns to ensure no missing values remain.

## Correlation Matrix and Dropping Highly Correlated Features
```python
# Update numeric columns after adding the 'type_numeric' column
numeric_columns = urls_data.select_dtypes(include=['int64', 'float64', 'int32', 'int8']).columns

# Calculate the correlation matrix
correlation_matrix = urls_data[numeric_columns].corr()

# Identify highly correlated features
threshold = 0.85
high_corr_pairs = [(column, correlation_matrix.index[i]) for i, row in enumerate(correlation_matrix.values) for j, column in enumerate(correlation_matrix.columns) if abs(row[j]) > threshold and i != j]

# Keep track of features to drop, ensuring only one feature per pair is dropped
features_to_drop = set()
already_dropped = set()

for feature_1, feature_2 in high_corr_pairs:
    if feature_1 not in features_to_drop and feature_2 not in features_to_drop:
        # Arbitrarily keep feature_1 and drop feature_2
        features_to_drop.add(feature_2)
        already_dropped.add(feature_1)

# Drop the highly correlated features
urls_data_reduced = urls_data.drop(columns=features_to_drop)

# Recalculate the correlation matrix for the reduced dataset
reduced_numeric_columns = urls_data_reduced.select_dtypes(include=['int64', 'float64', 'int32', 'int8']).columns
reduced_correlation_matrix = urls_data_reduced[reduced_numeric_columns].corr()

# Visualize the reduced correlation matrix
plt.figure(figsize=(16, 10))
sns.heatmap(reduced_correlation_matrix, annot=True, cmap='coolwarm')
plt.title('Correlation Matrix of Reduced Features')
plt.show()

# Output the list of dropped features
print("Dropped features due to high correlation:")
print(tabulate(pd.DataFrame(list(features_to_drop), columns=["Dropped Features"]), headers='keys', tablefmt='psql'))
```
This section calculates the correlation matrix, identifies highly correlated features, drops them, and visualizes the reduced correlation matrix.

## Displaying Initial Dataset Info and Handling Missing Values
```python
# Display initial dataset info and handle missing values
print("Initial dataset preview:")
print(tabulate(urls_data_reduced.head(), headers='keys', tablefmt='psql'))
print("\nMissing values in each column:")
print(tabulate(urls_data_reduced.isnull().sum().reset_index(), headers=['Column', 'Missing Values'], tablefmt='psql'))
print("\nDataset shape (rows, columns):", urls_data_reduced.shape)

# Drop duplicates and display updated dataset shape
urls_data_reduced.drop_duplicates(inplace=True)
print("\nShape after dropping duplicates:", urls_data_reduced.shape)

# Display dataset columns
print("\nDataset columns:")
print(tabulate(pd.DataFrame(urls_data_reduced.columns, columns=["Columns"]), headers='keys', tablefmt='psql'))
```
This part displays the initial dataset preview, handles missing values, drops duplicates, and prints the dataset columns.

## Dropping Unnecessary Columns and Splitting Data
```python
# Drop unnecessary columns
data = urls_data_reduced.drop(columns=['url', 'type', 'pri_domain'])
print("\nDataset preview after dropping unnecessary columns:")
print(tabulate(data.head(), headers='keys', tablefmt='psql'))

# Split data into features (X) and target (y)
X = data
y = urls_data_reduced['type']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Display the shapes of the training and testing sets
print("\nTraining and testing set shapes:")
print(tabulate(pd.DataFrame({"X_train": [X_train.shape], "y_train": [y_train.shape], "X_test": [X_test.shape], "y_test": [y_test.shape]}), headers='keys', tablefmt='psql'))
```
This final section drops unnecessary columns, splits the data into features and target, and then splits it into training and testing sets. It also prints the shapes of these sets for verification.

# URL Feature Extraction and Malicious URL Detection

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


