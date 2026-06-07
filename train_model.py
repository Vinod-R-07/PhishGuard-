import pandas as pd
from scipy.io import arff
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Load dataset
data, meta = arff.loadarff('dataset/Training Dataset.arff')
df = pd.DataFrame(data)
df = df.applymap(lambda x: int(x))

X = df.drop('Result', axis=1)
y = df['Result']

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, 'model/phishing_model.pkl')
print("Model saved!")