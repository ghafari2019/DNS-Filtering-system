# Import necessary libraries
import re
import string
import logging
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split, cross_val_score, cross_val_predict
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, classification_report, confusion_matrix
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, ExtraTreesClassifier, GradientBoostingClassifier, BaggingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier, LogisticRegression, RidgeClassifier, Perceptron
from sklearn.naive_bayes import GaussianNB, MultinomialNB
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.gaussian_process import GaussianProcessClassifier
from sklearn.mixture import GaussianMixture
from sklearn.cluster import KMeans
from sklearn.pipeline import Pipeline
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis, QuadraticDiscriminantAnalysis
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier
from tldextract import extract as tld_extract
from tld import get_tld, is_tld
from tld.exceptions import TldDomainNotFound, TldBadUrl, TldIOError
from colorama import Fore
from datetime import datetime
from plotly.subplots import make_subplots
from plotly import graph_objects as go
from wordcloud import WordCloud
from gensim.models import Word2Vec
import tldextract
import hashlib
import whois
import warnings
from sklearn.preprocessing import LabelEncoder
import ipaddress
from tabulate import tabulate

# Load dataset
urls_data = pd.read_csv(r'C:\Users\User\Desktop\cgi interview\malicious_phish.csv')

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

# Display the DataFrame with the new features
print(tabulate(urls_data.head(), headers='keys', tablefmt='psql'))

# Plot the count of different types of URLs
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

# Encoding and Labeling
le = LabelEncoder()

# Define a function to hash encode the root_domain
def hash_encode(category):
    hash_object = hashlib.md5(category.encode())
    return int(hash_object.hexdigest(), 16) % (10 ** 8)

# Display the value counts of the root_domain column
print("\nValue counts of 'root_domain' before filtering:")
print(tabulate(urls_data['root_domain'].value_counts().reset_index(), headers=['Root Domain', 'Count'], tablefmt='psql'))

# Filter out rows where root_domain is '0'
urls_data = urls_data[urls_data['root_domain'] != '0']
print("\nValue counts of 'root_domain' after filtering:")
print(tabulate(urls_data['root_domain'].value_counts().reset_index(), headers=['Root Domain', 'Count'], tablefmt='psql'))

# Display the number of unique values in the root_domain column
print("\nNumber of unique root_domain values:", len(urls_data['root_domain'].value_counts()))

# Apply the hash encoding function to the root_domain column
urls_data['root_domain'] = urls_data['root_domain'].apply(hash_encode)
urls_data['have_ip'] = urls_data['have_ip'].astype(int)
urls_data['type'] = le.fit_transform(urls_data['type'])

# Display the final DataFrame
print(tabulate(urls_data.head(), headers='keys', tablefmt='psql'))

# Handle missing values efficiently by filling with the median for numeric columns
numeric_columns = urls_data.select_dtypes(include=['int64', 'float64','int32','int8']).columns
urls_data[numeric_columns] = urls_data[numeric_columns].apply(lambda x: x.fillna(x.median()))
print(numeric_columns)

# Remove constant features
constant_features = [column for column in urls_data.columns if urls_data[column].nunique() == 1]
urls_data.drop(columns=constant_features, inplace=True)

# Update numeric columns after dropping constant features
numeric_columns = urls_data.select_dtypes(include=['int64', 'float64','int32','int8']).columns

# Check for any remaining missing values and fill them if necessary
urls_data[numeric_columns] = urls_data[numeric_columns].fillna(0)

# Update numeric columns after adding the 'type_numeric' column
numeric_columns = urls_data.select_dtypes(include=['int64', 'float64','int32','int8']).columns

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
reduced_numeric_columns = urls_data_reduced.select_dtypes(include=['int64', 'float64','int32','int8']).columns
reduced_correlation_matrix = urls_data_reduced[reduced_numeric_columns].corr()

# Visualize the reduced correlation matrix
plt.figure(figsize=(16, 10))
sns.heatmap(reduced_correlation_matrix, annot=True, cmap='coolwarm')
plt.title('Correlation Matrix of Reduced Features')
plt.show()

# Output the list of dropped features
print("Dropped features due to high correlation:")
print(tabulate(pd.DataFrame(list(features_to_drop), columns=["Dropped Features"]), headers='keys', tablefmt='psql'))

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
