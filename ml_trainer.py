import os
import glob
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# === CONFIGURATION ===
DATA_DIR = "/Users/lightwave/Downloads/archive/"
MODEL_FILENAME = "cic_ids_model.pkl"


def load_all_csvs(data_dir):
    all_files = glob.glob(os.path.join(data_dir, "*.csv"))
    df_list = []

    for file in all_files:
        try:
            print(f"Checking {file} ...")
            df = pd.read_csv(file, low_memory=False)
            df.columns = df.columns.str.strip()
            if "Label" not in df.columns:
                print(f"⚠️ Skipping {file} — no 'Label' column. columns are {df.columns}")
                continue

            df_list.append(df)
        except Exception as e:
            print(f"❌ Error reading {file}: {e}")

    if not df_list:
        raise ValueError("No CSV files with a 'Label' column were found.")

    return pd.concat(df_list, ignore_index=True)


def preprocess_data(df):
    print("Initial shape:", df.shape)

    # Remove unnamed columns
    df = df.loc[:, ~df.columns.str.contains("^Unnamed")]

    # Drop rows with NaN or infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Convert labels to binary: 0 for BENIGN, 1 for attack
    df = df[df["Label"].notna()]
    df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

    # Separate features and label
    X = df.drop("Label", axis=1)
    y = df["Label"]

    # Convert non-numeric columns
    X = pd.get_dummies(X)

    # Scale the features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y, scaler


def train_model(X_train, y_train):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model


def main():
    print("Loading data...")
    df = load_all_csvs(DATA_DIR)

    print("Preprocessing...")
    X, y, scaler = preprocess_data(df)

    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training model...")
    model = train_model(X_train, y_train)

    print("Evaluating model...")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    print(f"Saving model to {MODEL_FILENAME} ...")
    joblib.dump({"model": model, "scaler": scaler}, MODEL_FILENAME)

    print("Done.")


if __name__ == "__main__":
    main()
