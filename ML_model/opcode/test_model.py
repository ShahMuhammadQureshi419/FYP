import os
import json
import joblib
import pandas as pd
import numpy as np
from glob import glob
from sklearn.preprocessing import normalize

os.environ["LOKY_MAX_CPU_COUNT"] = "4"

# ========== Config ==========
MODEL_DIR = "saved_models"
opcode_file = os.path.join(MODEL_DIR, "opcode_columns.json")

with open(opcode_file, "r") as f:
    opcode_columns = json.load(f)

# Clean function (same used in training)
def clean_column_name(name):
    return str(name).replace('"', '_').replace('\\', '_').replace('/', '_').replace('$', '_').replace(':', '_').replace('-', '_')

opcode_columns_cleaned = [clean_column_name(col) for col in opcode_columns]

# Load models and encoders
model_variants = ["et", "xgb", "lgbm"]
model_types = ["type", "category", "family"]

models = {
    variant: {
        mtype: joblib.load(os.path.join(MODEL_DIR, f"{variant}_{mtype}_classifier.joblib"))
        for mtype in model_types
        if os.path.exists(os.path.join(MODEL_DIR, f"{variant}_{mtype}_classifier.joblib"))
    }
    for variant in model_variants
}

encoders = {
    variant: {
        mtype: joblib.load(os.path.join(MODEL_DIR, f"{variant}_{mtype}_classifier_label_encoder.joblib"))
        for mtype in model_types
        if os.path.exists(os.path.join(MODEL_DIR, f"{variant}_{mtype}_classifier_label_encoder.joblib"))
    }
    for variant in model_variants
}

# ========== User Input ==========
json_folder = input("Enter path to folder containing opcode JSON files: ").strip('"')
json_files = glob(os.path.join(json_folder, "*.json"))

# ========== Process Each JSON ==========
for json_path in json_files:
    print(f"\n=== Processing: {os.path.basename(json_path)} ===")
    try:
        with open(json_path, "r") as f:
            data = json.load(f)

        opcodes = data.get("Static_analysis", {}).get("Opcodes", {})
        opcodes_cleaned = {clean_column_name(k): v for k, v in opcodes.items()}

        # Build full feature vector
        feature_vector = {col: opcodes_cleaned.get(col, 0) for col in opcode_columns_cleaned}
        df = pd.DataFrame([feature_vector])
        df_norm = pd.DataFrame(normalize(df, norm='l1'), columns=opcode_columns_cleaned)

        # Loop through all model variants
        for variant in model_variants:
            if "type" not in models[variant]:
                continue

            print(f"\n🔍 {variant.upper()} Predictions:")

            type_model = models[variant]["type"]
            type_encoder = encoders[variant].get("type")
            type_pred = type_model.predict(df_norm)
            if type_encoder:
                type_pred = type_encoder.inverse_transform(type_pred)
            type_proba = type_model.predict_proba(df_norm)[0]
            type_conf = max(type_proba)
            predicted_type = type_pred[0]

            if predicted_type == "malware" and type_conf < 0.65:
                predicted_type = "benign"
            print(f"📌 Type: {predicted_type} (Confidence: {type_conf:.2f})")

            if predicted_type == "malware":
                # Category
                category = models[variant].get("category")
                cat_encoder = encoders[variant].get("category")
                if category:
                    cat_pred = category.predict(df_norm)
                    if cat_encoder:
                        cat_pred = cat_encoder.inverse_transform(cat_pred)
                    print(f"📌 Category: {cat_pred[0]}")

                # Family
                family = models[variant].get("family")
                fam_encoder = encoders[variant].get("family")
                if family:
                    fam_pred = family.predict(df_norm)
                    if fam_encoder:
                        fam_pred = fam_encoder.inverse_transform(fam_pred)
                    print(f"📌 Family: {fam_pred[0]}")
            else:
                print("✅ App is benign — category/family prediction skipped.")

    except Exception as e:
        print(f"❌ Error processing {json_path}: {e}")
