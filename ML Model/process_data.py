from define_functions import *
from tabulate import tabulate
import pandas as pd
import plotly.graph_objects as go
import seaborn as sns
import matplotlib.pyplot as plt
from wordcloud import WordCloud

# Load dataset
urls_data = pd.read_csv(r'C:\Users\User\Desktop\cgi interview\malicious_phish.csv')

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

# Visualization: Word Cloud of URLs
wordcloud = WordCloud(width=800, height=400, background_color='white').generate(' '.join(urls_data['url']))
plt.figure(figsize=(10, 6))
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis('off')
plt.title('Word Cloud of URLs')
plt.show()

# Pie chart for 'url_type' column
url_type_counts = urls_data['type'].value_counts()
fig = go.Figure(data=[go.Pie(labels=url_type_counts.index, values=url_type_counts.values)])
fig.update_layout(title='Distribution of URL Types',
                  template='plotly_dark',
                  font=dict(color='white'),
                  showlegend=True)
fig.show()


