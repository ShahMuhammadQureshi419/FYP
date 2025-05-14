import json
import os
import joblib
import pandas as pd
import numpy as np
from glob import glob

# === Config ===
MODEL_DIR = "saved_models"
SCALER_FILE = os.path.join(MODEL_DIR, "permission_scaler.joblib")
PERMISSION_COLUMNS_FILE = os.path.join(MODEL_DIR, "permission_columns.json")

# Load all classifiers
model_variants = ["et", "rf", "gbc"]
model_types = ["type", "category", "family"]

models = {
    model_type: {
        variant: joblib.load(os.path.join(MODEL_DIR, f"{model_type}_classifier_{variant}.joblib"))
        for variant in model_variants
    }
    for model_type in model_types
}

# Load scaler and permission columns
with open(PERMISSION_COLUMNS_FILE, "r") as f:
    permission_columns = json.load(f)

scaler = joblib.load(SCALER_FILE)

# === Load JSON files ===
json_folder = input("Enter path to folder containing JSON files: ")
json_files = glob(os.path.join(json_folder, "*.json"))

# === Process each file ===
for json_file in json_files:
    print(f"\n=== Processing: {os.path.basename(json_file)} ===")

    try:
        with open(json_file, "r") as f:
            data = json.load(f)

        permissions = data.get("Static_analysis", {}).get("Permissions", [])
        permissions = [perm.strip() for perm in permissions]

        # Binary vector
        perm_vector = {perm: 0 for perm in permission_columns}
        for p in permissions:
            if p in perm_vector:
                perm_vector[p] = 1

        df_input = pd.DataFrame([perm_vector])
        df_scaled = pd.DataFrame(scaler.transform(df_input), columns=permission_columns)

        # === Predictions from each model variant ===
        for variant in model_variants:
            print(f"\n🔍 {variant.upper()} Predictions:")

            # --- Type ---
            type_model = models["type"][variant]
            type_proba = type_model.predict_proba(df_scaled.to_numpy())[0]
            type_idx = np.argmax(type_proba)
            predicted_type = type_model.classes_[type_idx]
            type_confidence = type_proba[type_idx]

            if predicted_type == "malware" and type_confidence < 0.65:
                predicted_type = "benign"

            print(f"📌 Type: {predicted_type} (Confidence: {type_confidence:.2f})")

            # --- Category & Family ---
            if predicted_type == "malware":
                category = models["category"][variant].predict(df_scaled.to_numpy)[0]
                family = models["family"][variant].predict(df_scaled.to_numpy)[0]
                print(f"📌 Category: {category}")
                print(f"📌 Family: {family}")
            else:
                print("✅ App is benign — category/family prediction skipped.")

    except Exception as e:
        print(f"❌ Error processing {json_file}: {e}")
