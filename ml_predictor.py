import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import normalize

import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import warnings
warnings.filterwarnings("ignore")


import xgboost as xgb
xgb.set_config(verbosity=0)


def clean_column_name(name):
    return str(name).replace('"', '_').replace('\\', '_').replace('/', '_')\
        .replace('$', '_').replace(':', '_').replace('-', '_')


class MLPredictor:
    def __init__(self):
        base_path = os.path.join(os.path.dirname(__file__), 'ML_model')
        self.opcode_path = os.path.join(base_path, 'opcode')
        self.permission_path = os.path.join(base_path, 'permission')

        self.opcode_models, self.opcode_encoders = self.load_models_and_encoders(
            self.opcode_path, ['et', 'lgbm', 'xgb'])
        self.permission_models, self.permission_encoders = self.load_models_and_encoders(
            self.permission_path, ['rf', 'et', 'gbc'])

        with open(os.path.join(self.opcode_path, 'opcode_columns.json')) as f:
            raw_opcode_cols = json.load(f)
        self.opcode_columns = [clean_column_name(c) for c in raw_opcode_cols]

        with open(os.path.join(self.permission_path, 'permission_columns.json')) as f:
            self.permission_columns = json.load(f)

        self.permission_scaler = joblib.load(os.path.join(self.permission_path, 'permission_scaler.joblib'))

    def load_models_and_encoders(self, path, variants):
        models = {}
        encoders = {}
        for variant in variants:
            models[variant] = {}
            encoders[variant] = {}
            for label in ['type', 'category', 'family']:
                model_path = os.path.join(path, f"{variant}_{label}_classifier.joblib")
                models[variant][label] = joblib.load(model_path)

                encoder_path = os.path.join(path, f"{variant}_{label}_classifier_label_encoder.joblib")
                if os.path.exists(encoder_path):
                    encoders[variant][label] = joblib.load(encoder_path)
        return models, encoders

    def predict_from_opcode(self, json_data):
        opcodes = json_data.get("Static_analysis", {}).get("Opcodes", {})
        opcodes_cleaned = {clean_column_name(k): v for k, v in opcodes.items()}

        feature_vector = {col: opcodes_cleaned.get(col, 0) for col in self.opcode_columns}
        df = pd.DataFrame([feature_vector])
        df_norm = pd.DataFrame(normalize(df, norm='l1'), columns=self.opcode_columns)

        predictions = []
        category_preds = []
        family_preds = []

        for variant, model_set in self.opcode_models.items():
            print(f"\n🔍 {variant.upper()} Opcode Predictions:")

            type_model = model_set['type']
            type_encoder = self.opcode_encoders[variant].get('type')
            type_pred = type_model.predict(df_norm)
            if type_encoder:
                type_pred = type_encoder.inverse_transform(type_pred)
            type_conf = max(type_model.predict_proba(df_norm)[0])
            pred_type = type_pred[0]
            if pred_type == 'malware' and type_conf < 0.65:
                pred_type = 'benign'

            print(f"📌 Type: {pred_type} (Confidence: {type_conf:.2f})")
            predictions.append(pred_type)

            if pred_type == 'malware':
                cat_model = model_set['category']
                fam_model = model_set['family']

                cat_pred = cat_model.predict(df_norm)
                fam_pred = fam_model.predict(df_norm)

                if self.opcode_encoders[variant].get('category'):
                    cat_pred = self.opcode_encoders[variant]['category'].inverse_transform(cat_pred)
                if self.opcode_encoders[variant].get('family'):
                    fam_pred = self.opcode_encoders[variant]['family'].inverse_transform(fam_pred)

                category_preds.append(cat_pred[0])
                family_preds.append(fam_pred[0])

        return predictions, category_preds, family_preds

    def predict_from_permission(self, json_data):
        permissions = json_data.get("Static_analysis", {}).get("Permissions", [])
        permissions = [p.strip() for p in permissions]

        perm_vector = {perm: 0 for perm in self.permission_columns}
        for p in permissions:
            if p in perm_vector:
                perm_vector[p] = 1

        df_input = pd.DataFrame([perm_vector])
        df_scaled = pd.DataFrame(self.permission_scaler.transform(df_input), columns=self.permission_columns)

        predictions = []
        category_preds = []
        family_preds = []

        for variant, model_set in self.permission_models.items():
            print(f"\n🔍 {variant.upper()} Permission Predictions:")

            type_model = model_set['type']
            type_proba = type_model.predict_proba(df_scaled.to_numpy())[0]
            type_idx = np.argmax(type_proba)
            pred_type = type_model.classes_[type_idx]
            type_conf = type_proba[type_idx]

            if pred_type == 'malware' and type_conf < 0.65:
                pred_type = 'benign'

            print(f"📌 Type: {pred_type} (Confidence: {type_conf:.2f})")
            predictions.append(pred_type)

            if pred_type == 'malware':
                category = model_set['category'].predict(df_scaled)[0]
                family = model_set['family'].predict(df_scaled)[0]
                category_preds.append(category)
                family_preds.append(family)

        return predictions, category_preds, family_preds


    def predict_all(self, json_path):
        with open(json_path, "r") as f:
            json_data = json.load(f)

        op_preds, op_cats, op_fams = self.predict_from_opcode(json_data)
        perm_preds, perm_cats, perm_fams = self.predict_from_permission(json_data)

        combined_preds = op_preds + perm_preds
        malware_votes = sum(1 for p in combined_preds if p == 'malware')

        final_type = 'malware' if malware_votes >= 4 else 'benign'
        print(f"\n🔎 Final Decision (Majority Voting): {final_type} (Malware votes: {malware_votes}/6)")

        result = {'type': final_type, 'malware_votes': malware_votes, 'individual_preds': combined_preds}

        if final_type == 'malware':
            all_cats = op_cats + perm_cats
            all_fams = op_fams + perm_fams
            result['category'] = max(set(all_cats), key=all_cats.count) if all_cats else 'unknown'
            result['family'] = max(set(all_fams), key=all_fams.count) if all_fams else 'unknown'

        return result
