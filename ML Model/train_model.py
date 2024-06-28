
exec(open('import_libraries.py').read())
exec(open('define_functions.py').read())
exec(open('process_data.py').read())

# Assuming 'urls_data_reduced', 'X', 'y', 'X_train', 'X_test', 'y_train', 'y_test' are available from process_data.py

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Define the XGBoost model
xgb_model = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')

# Define the parameter grid for hyperparameter tuning
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [3, 5, 7],
    'learning_rate': [0.01, 0.1, 0.2],
    'subsample': [0.8, 1.0],
    'colsample_bytree': [0.8, 1.0]
}

# Initialize the GridSearchCV object
grid_search = GridSearchCV(estimator=xgb_model, param_grid=param_grid, cv=5, scoring='accuracy', n_jobs=-1, verbose=2)

# Perform the grid search
grid_search.fit(X_train, y_train)

# Get the best parameters and the best model
best_params = grid_search.best_params_
best_xgb_model = grid_search.best_estimator_

print(f"Best parameters: {best_params}")

# Save the best model
joblib.dump(best_xgb_model, 'best_xgboost_model.joblib')

# Evaluate the best model on the test data
y_pred_best = best_xgb_model.predict(X_test)
accuracy_best = accuracy_score(y_test, y_pred_best)
recall_best = recall_score(y_test, y_pred_best, average='weighted')
precision_best = precision_score(y_test, y_pred_best, average='weighted', zero_division=1)
f1_best = f1_score(y_test, y_pred_best, average='weighted')

print(f"Best Test Accuracy: {accuracy_best}")
print(f"Best Test Recall: {recall_best}")
print(f"Best Test Precision: {precision_best}")
print(f"Best Test F1-Score: {f1_best}")


