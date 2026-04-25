import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


print("Loading dataset...")

data = pd.read_csv("dataset/dataset.csv")

if "index" in data.columns:
    data = data.drop("index", axis=1)

print("Dataset shape:", data.shape)
print("Class distribution:\n", data["Result"].value_counts())

X = data.drop("Result", axis=1)
y = data["Result"]

print("\nFeature columns:", list(X.columns))
print("Total features:", len(X.columns))

print("\nSplitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42
)

print("Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

print("Evaluating model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nModel Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Phishing (-1)", "Legitimate (1)"]))

print("Saving model...")
with open("model/phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("model/feature_columns.pkl", "wb") as f:
    pickle.dump(list(X.columns), f)

print("\nSaved:")
print("  model/phishing_model.pkl")
print("  model/feature_columns.pkl")
print("\nTraining complete.")
