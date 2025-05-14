import os
import json
import joblib
import numpy as np

class MLPredictor:
    def __init__(self):
        # Define model paths
        base_path = os.path.join(os.path.dirname(__file__), 'ML_model')
        self.opcode_path = os.path.join(base_path, 'opcode')
        self.permission_path = os.path.join(base_path, 'permission')

        # Load models
        self.opcode_models = self.load_models(self.opcode_path, ['et', 'lgbm', 'xgb'])
        self.permission_models = self.load_models(self.permission_path, ['rf', 'et', 'gbc'])

        # Load columns
        with open(os.path.join(self.opcode_path, 'opcode_columns.json')) as f:
            self.opcode_columns = json.load(f)
        with open(os.path.join(self.permission_path, 'permission_columns.json')) as f:
            self.permission_columns = json.load(f)

        # Load scaler for permission
        self.permission_scaler = joblib.load(os.path.join(self.permission_path, 'permission_scaler.joblib'))

    def load_models(self, path, model_names):
        models = {}
        for name in model_names:
            models[name] = {
                'type': joblib.load(os.path.join(path, f"{name}_type_classifier.joblib")),
                'category': joblib.load(os.path.join(path, f"{name}_category_classifier.joblib")),
                'family': joblib.load(os.path.join(path, f"{name}_family_classifier.joblib")),
                'type_encoder': joblib.load(os.path.join(path, f"{name}_type_classifier_label_encoder.joblib")),
                'category_encoder': joblib.load(os.path.join(path, f"{name}_category_classifier_label_encoder.joblib")),
                'family_encoder': joblib.load(os.path.join(path, f"{name}_family_classifier_label_encoder.joblib"))
            }
        return models

    def prepare_features(self, feature_dict, feature_type):
        if feature_type == 'opcode':
            vector = [feature_dict.get(col, 0) for col in self.opcode_columns]
        else:
            vector = [feature_dict.get(col, 0) for col in self.permission_columns]
            vector = self.permission_scaler.transform([vector])[0]
        return np.array([vector])

    def predict_all(self, opcode_features: dict, permission_features: dict):
        predictions = []

        # Predict from opcode models
        for model in self.opcode_models.values():
            features = self.prepare_features(opcode_features, 'opcode')
            pred = model['type'].predict(features)[0]
            predictions.append(model['type_encoder'].inverse_transform([pred])[0])

        # Predict from permission models
        for model in self.permission_models.values():
            features = self.prepare_features(permission_features, 'permission')
            pred = model['type'].predict(features)[0]
            predictions.append(model['type_encoder'].inverse_transform([pred])[0])

        # Majority voting
        malware_votes = sum(1 for pred in predictions if pred == 'malware')
        final_type = 'malware' if malware_votes >= 4 else 'benign'

        final_result = {'type': final_type}

        # If malware, also get category and family from all models
        if final_type == 'malware':
            category_preds = []
            family_preds = []

            for model in self.opcode_models.values():
                features = self.prepare_features(opcode_features, 'opcode')
                category = model['category'].predict(features)[0]
                family = model['family'].predict(features)[0]
                category_preds.append(model['category_encoder'].inverse_transform([category])[0])
                family_preds.append(model['family_encoder'].inverse_transform([family])[0])

            for model in self.permission_models.values():
                features = self.prepare_features(permission_features, 'permission')
                category = model['category'].predict(features)[0]
                family = model['family'].predict(features)[0]
                category_preds.append(model['category_encoder'].inverse_transform([category])[0])
                family_preds.append(model['family_encoder'].inverse_transform([family])[0])

            # Most common category and family
            final_result['category'] = max(set(category_preds), key=category_preds.count)
            final_result['family'] = max(set(family_preds), key=family_preds.count)

        return final_result
