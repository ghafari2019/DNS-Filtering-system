# URL Classification Project

## Overview
This project aims to classify URLs into different types (benign, defacement, phishing, malware) using various machine learning models. The project involves feature extraction from URLs and evaluating multiple classifiers to identify the best-performing model.

## Dataset
The dataset contains URLs and their corresponding types:
- **URL**: The URL to be classified.
- **Type**: The type of the URL (benign, defacement, phishing, malware).

## Project Structure
- `import_libraries.py`: Script to import necessary libraries.
- `define_functions.py`: Script defining functions for feature extraction from URLs.
- `process_data.py`: Script to load, clean, and preprocess the data.
- `train_model.py`: Script to train and evaluate machine learning models.
- `model_selection.py`: Script to evaluate multiple classifiers and identify the best-performing model.

## Data Processing
### Feature Extraction
The features are extracted from the URLs using functions defined in `define_functions.py`. These features include various characteristics of the URLs that help in classification.

## Results

### 1. Correlation Matrix
The correlation matrix plot shows the relationship between different features and the target variable (type). It helps to identify which features are more relevant for the classification task.

![Correlation Matrix](correlation.png)

### 2. Count of Different Types of URLs
This bar plot displays the distribution of different URL types in the dataset. It helps to understand the class imbalance in the dataset.

![Count of Different Types of URLs](plot1.png)

### 3. Distribution of URL Types
This pie chart shows the percentage distribution of each URL type in the dataset, providing a visual representation of the class proportions.

![Distribution of URL Types](plot3.png)

### 4. Word Cloud of URLs
The word cloud visualizes the most common terms found in the URLs. It helps to understand the common patterns and words used in different types of URLs.

![Word Cloud of URLs](word_cloud.png)

### Data Splitting
The data is split into training and testing sets to evaluate model performance.

## Model Selection and Training
### Models Used
The following classifiers were evaluated:
- DecisionTreeClassifier
- RandomForestClassifier
- AdaBoostClassifier
- KNeighborsClassifier
- ExtraTreesClassifier
- GaussianNB
- XGBClassifier
- LGBMClassifier
- SVC


### Evaluation Method
The models were evaluated using 5-fold cross-validation. The performance metrics included accuracy, recall, precision, and F1 score.

#### 1. Classifier Performance Comparison
This bar plot compares the performance metrics (accuracy, precision, recall, F1 score) of different classifiers. The XGBClassifier shows the highest performance across all metrics.

![Comparison of Classifier Performance Metrics](models_comparison.png)

### 2. Classifier Performance Table
This table summarizes the performance of each classifier in terms of accuracy, precision, recall, and F1 score.

## Classifier Performance Table

| **Model**                | **Accuracy** | **Precision** | **Recall** | **F1-Score** |
|--------------------------|--------------|---------------|------------|--------------|
| XGBClassifier            | 0.938        | 0.936         | 0.938      | 0.936        |
| RandomForestClassifier   | 0.937        | 0.935         | 0.937      | 0.935        |
| ExtraTreesClassifier     | 0.934        | 0.932         | 0.934      | 0.933        |
| LGBMClassifier           | 0.934        | 0.932         | 0.934      | 0.932        |
| DecisionTreeClassifier   | 0.915        | 0.915         | 0.915      | 0.915        |
| KNeighborsClassifier     | 0.825        | 0.812         | 0.825      | 0.813        |
| GaussianNB               | 0.670        | 0.779         | 0.670      | 0.538        |
| SVC                      | 0.670        | 0.779         | 0.670      | 0.538        |
| AdaBoostClassifier       | 0.492        | 0.822         | 0.492      | 0.522        |


## Results
### Performance Metrics
The XGBClassifier outperformed the other models with the highest accuracy and balanced performance across all metrics.

### Hyperparameter Tuning
- The XGBClassifier was used with specific parameters to enhance performance.
- The LGBMClassifier was instantiated with verbosity reduced to disable logs.


## Discussion
### Interpretation of Results
- The XGBClassifier demonstrated superior performance in classifying URLs, making it the best choice for this task.

## Model Evaluation Results

| **Metric**                | **Value**  |
|---------------------------|------------|
| **Best Parameters**       |            |
| colsample_bytree          | 1.0        |
| learning_rate             | 0.2        |
| max_depth                 | 7          |
| n_estimators              | 300        |
| subsample                 | 0.8        |
| **Best Test Accuracy**    | 0.95       |
| **Best Test Recall**      | 0.95       |
| **Best Test Precision**   | 0.95       |
| **Best Test F1-Score**    | 0.95       |



### Model Strengths and Weaknesses
- **Strengths**: High accuracy, good balance between precision and recall.
- **Weaknesses**: Occasionally predicts false positives.

### Business Implications
- This model can be used to identify malicious URLs, enhancing security measures for users effectively.

### Future Work
- Further exploration of other algorithms and more extensive hyperparameter tuning.
- Incorporation of additional features and larger datasets to improve model robustness.

## How to Run
1. Clone the repository:
    ```bash
    git clone https://github.com/ghafari2019/DNS-Filtering-system.git
    ```
2. Navigate to the project directory:
    ```bash
    cd DNS-Filtering-system
    ```
3. Create and Write to requirements.txt Using Echo:    
```bash
echo numpy==2.0.0 > requirements.txt
echo pandas==2.2.2 >> requirements.txt
echo seaborn==0.13.2 >> requirements.txt
echo matplotlib==3.9.0 >> requirements.txt
echo scikit-learn==1.5.0 >> requirements.txt
echo xgboost==2.1.0 >> requirements.txt
echo lightgbm==4.3.0 >> requirements.txt
echo catboost==1.2.5 >> requirements.txt
echo tldextract==5.1.2 >> requirements.txt
echo tld==0.13 >> requirements.txt
echo colorama==0.4.6 >> requirements.txt
echo plotly==5.22.0 >> requirements.txt
echo wordcloud==1.9.3 >> requirements.txt
echo gensim==4.3.2 >> requirements.txt
echo whois==1.20240129.2 >> requirements.txt
echo tabulate==0.9.0 >> requirements.txt
```
4. Install required libraries:
    ```bash
    pip install -r requirements.txt
    ```
5. Run the scripts in the following order:
    ```bash
    python import_libraries.py
    python define_functions.py
    python process_data.py
    python model_selection.py
    python train_model.py
    ```

## Conclusion
This project demonstrates an effective approach to classifying URLs using machine learning. By identifying potentially harmful URLs, it enhances the overall security measures for web users.

## Acknowledgements
- Data source: [URL dataset](#)
- Libraries: `scikit-learn`, `xgboost`, `lightgbm`, `pandas`, `numpy`, `matplotlib`, `seaborn`

## Visualizations
- Include visualizations such as the classifier accuracy comparison plot, confusion matrix, and ROC curve here.

---

Feel free to modify this `README.md` file according to the specific details and results of your project.

