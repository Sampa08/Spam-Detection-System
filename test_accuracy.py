from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pandas as pd
import re
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from email_classifier import classify_email
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

def preprocess_text(text):
    """Clean and normalize text"""
    text = str(text).lower()
    # Remove URLs
    text = re.sub(r'http\S+|www\S+|https\S+', '[URL]', text, flags=re.MULTILINE)
    # Remove email addresses
    text = re.sub(r'\S+@\S+', '[EMAIL]', text)
    # Remove phone numbers
    text = re.sub(r'\d{10}|\d{3}[-.\s]\d{3}[-.\s]\d{4}', '[PHONE]', text)
    # Remove extra whitespace
    text = ' '.join(text.split())
    return text

# Load dataset
df = pd.read_csv("/home/mjsampa/Desktop/SPAM DETECTION NEW/combined_messages.csv")

# Clean the data
df['message'] = df['message'].fillna('')  # Handle missing values
df['message'] = df['message'].apply(preprocess_text)

# Remove duplicates
df = df.drop_duplicates(subset=['message'])

# Print initial class distribution
print("Initial class distribution:")
class_dist = df['filename'].apply(lambda x: 'spam' if 'spam' in str(x).lower() 
                        else ('scam' if 'scam' in str(x).lower() else 'ham')).value_counts()
print(class_dist)

# Balance classes (with error handling)
min_class_size = class_dist.min()
print(f"\nMinimum class size: {min_class_size}")

balanced_df = pd.DataFrame()
for label in ['spam', 'scam', 'ham']:
    subset = df[df['filename'].str.contains(label, case=False)]
    subset_size = len(subset)
    print(f"\nProcessing {label} class: {subset_size} samples")
    
    if subset_size == 0:
        print(f"Warning: No samples found for class {label}")
        continue
    
    # Take min(available samples, min_class_size)
    n_samples = min(subset_size, min_class_size)
    balanced_df = pd.concat([balanced_df, subset.sample(n=n_samples, random_state=42)])

if len(balanced_df) == 0:
    print("Error: No samples in balanced dataset. Check your class labels.")
    exit(1)

# Use balanced dataset
X = balanced_df['message']
y = balanced_df['filename'].apply(lambda x: 'spam' if 'spam' in str(x).lower() 
                        else ('scam' if 'scam' in str(x).lower() else 'ham'))

print("\nFinal balanced class distribution:")
print(y.value_counts())

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Get predictions
y_pred = [classify_email(text) for text in X_test]

# Calculate metrics
accuracy = accuracy_score(y_test, y_pred)
print(f"\nOverall Accuracy: {accuracy:.3f}")

# Detailed classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8,6))
sns.heatmap(cm, annot=True, fmt='d', 
            xticklabels=['ham','scam','spam'],
            yticklabels=['ham','scam','spam'])
plt.title('Confusion Matrix')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.savefig('confusion_matrix.png')
plt.close()

# Save misclassified examples
test_df = pd.DataFrame({
    'message': X_test,
    'true_label': y_test,
    'predicted': y_pred,
    'filename': df['filename'][X_test.index]
})
test_df['correct'] = test_df['true_label'] == test_df['predicted']
test_df[~test_df['correct']].to_csv('misclassified.csv', index=False)

# Print summary statistics
print("\nDataset Statistics:")
print(f"Total samples: {len(df)}")
print("\nClass distribution:")
print(y.value_counts())
print("\nMisclassified examples saved to 'misclassified.csv'")
print("Confusion matrix plot saved to 'confusion_matrix.png'")

# Sample predictions
print("\nSample Predictions (first 5):")
for i in range(min(5, len(X_test))):
    print(f"\nMessage: {X_test.iloc[i][:100]}...")
    print(f"True: {y_test.iloc[i]}, Predicted: {y_pred[i]}")

# Create pipeline
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        min_df=2,
        max_df=0.95,
        ngram_range=(1, 2),
        stop_words='english'
    )),
    ('clf', RandomForestClassifier(
        n_estimators=100,
        random_state=42
    ))
])

# Perform 5-fold cross-validation
cv_scores = cross_val_score(pipeline, X, y, cv=5)
print("\nCross-validation scores:", cv_scores)
print(f"Average CV accuracy: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")