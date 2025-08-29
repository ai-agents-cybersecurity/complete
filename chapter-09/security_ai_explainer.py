import pandas as pd
import numpy as np
import shap
import lime
import lime.tabular
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import warnings
warnings.filterwarnings('ignore')

class SecurityAIExplainer:
    def __init__(self):
        self.models = {}
        self.explainers = {}
        self.scalers = {}
        self.feature_names = []
    def prepare_malware_data(self, n_samples=1000):
        np.random.seed(42)
        features = {}
        features['CreateProcess_calls'] = np.random.poisson(5, n_samples)
        features['RegCreateKey_calls'] = np.random.poisson(3, n_samples)
        features['WriteFile_calls'] = np.random.poisson(10, n_samples)
        features['InternetConnect_calls'] = np.random.poisson(2, n_samples)
        features['files_created'] = np.random.poisson(8, n_samples)
        features['files_deleted'] = np.random.poisson(2, n_samples)
        features['registry_modifications'] = np.random.poisson(4, n_samples)
        features['network_connections'] = np.random.poisson(3, n_samples)
        features['dns_queries'] = np.random.poisson(15, n_samples)
        features['suspicious_domains'] = np.random.poisson(1, n_samples)
        features['process_injections'] = np.random.poisson(1, n_samples)
        features['persistence_mechanisms'] = np.random.poisson(1, n_samples)
        features['crypto_operations'] = np.random.poisson(2, n_samples)
        data = pd.DataFrame(features)
        malware_indicators = (
            (data['CreateProcess_calls'] > 10) |
            (data['RegCreateKey_calls'] > 8) |
            (data['process_injections'] > 2) |
            (data['suspicious_domains'] > 3) |
            (data['persistence_mechanisms'] > 2)
        )
        noise = np.random.random(n_samples)
        labels = ((malware_indicators.astype(int) * 0.8 + noise * 0.2) > 0.5).astype(int)
        data['is_malware'] = labels
        return data
    def train_models(self, data, target_column, model_types=['rf', 'gb', 'lr']):
        X = data.drop(columns=[target_column])
        y = data[target_column]
        self.feature_names = X.columns.tolist()
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        self.scalers['scaler'] = scaler
        models_config = {
            'rf': RandomForestClassifier(n_estimators=100, random_state=42),
            'gb': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'lr': LogisticRegression(random_state=42, max_iter=1000)
        }
        for model_name in model_types:
            if model_name not in models_config:
                continue
            model = models_config[model_name]
            if model_name == 'lr':
                model.fit(X_train_scaled, y_train)
                y_pred = model.predict(X_test_scaled)
                self.models[model_name] = {'model': model, 'scaled': True}
            else:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                self.models[model_name] = {'model': model, 'scaled': False}
            accuracy = accuracy_score(y_test, y_pred)
            print(f"{model_name.upper()} Accuracy: {accuracy:.3f}")
        return X_train, X_test, y_train, y_test
    def explain_with_shap(self, model_name, X_sample, sample_index=0):
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")
        model_info = self.models[model_name]
        model = model_info['model']
        if model_info['scaled']:
            X_sample = self.scalers['scaler'].transform(X_sample)
        if model_name in ['rf', 'gb']:
            explainer = shap.TreeExplainer(model)
        else:
            explainer = shap.LinearExplainer(model, X_sample)
        shap_values = explainer.shap_values(X_sample)
        if len(shap_values) > 1:
            shap_values = shap_values[1]
        return shap_values
    def explain_with_lime(self, model_name, X_train, X_sample, sample_index=0):
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")
        model_info = self.models[model_name]
        model = model_info['model']
        if model_info['scaled']:
            X_train_lime = self.scalers['scaler'].transform(X_train)
            X_sample_lime = self.scalers['scaler'].transform(X_sample)
        else:
            X_train_lime = X_train
            X_sample_lime = X_sample
        explainer = lime.tabular.LimeTabularExplainer(
            X_train_lime,
            feature_names=self.feature_names,
            class_names=['Benign', 'Malicious'],
            mode='classification'
        )
        def predict_fn(x):
            return model.predict_proba(x)
        explanation = explainer.explain_instance(
            X_sample_lime[sample_index],
            predict_fn,
            num_features=len(self.feature_names)
        )
        return explanation
class TrustThroughTransparencyFramework:
    def __init__(self):
        self.transparency_levels = {
            'BASIC': 'Simple confidence scores and basic feature importance',
            'DETAILED': 'Full feature attributions with explanatory text',
            'COMPREHENSIVE': 'Multi-method explanations with uncertainty quantification',
            'INTERACTIVE': 'Real-time explanations with what-if analysis'
        }
    def assess_explanation_needs(self, use_case, stakeholder, decision_impact):
        requirements = {
            ('malware_detection', 'analyst', 'high'): 'COMPREHENSIVE',
            ('malware_detection', 'analyst', 'medium'): 'DETAILED',
            ('malware_detection', 'executive', 'high'): 'DETAILED',
            ('intrusion_detection', 'analyst', 'high'): 'COMPREHENSIVE',
            ('fraud_detection', 'compliance', 'high'): 'INTERACTIVE',
            ('automated_response', 'operator', 'critical'): 'INTERACTIVE'
        }
        key = (use_case, stakeholder, decision_impact)
        return requirements.get(key, 'DETAILED')
    def generate_explanation_narrative(self, explanations, use_case="malware_detection"):
        if 'top_features' not in explanations:
            return "Insufficient explanation data available."
        top_features = explanations['top_features'][:5]
        confidence = explanations.get('prediction_confidence', [0.5, 0.5])
        is_malicious = confidence[1] > confidence[0]
        confidence_level = max(confidence)
        narrative = f"""
        SECURITY AI ANALYSIS REPORT
        ===========================
        VERDICT: {'MALICIOUS' if is_malicious else 'BENIGN'} (Confidence: {confidence_level:.1%})
        REASONING:
        The AI model analyzed {len(explanations.get('top_features', []))} behavioral indicators and identified the following key factors:
        TOP CONTRIBUTING FACTORS:
        """
        for i, (feature, impact, value) in enumerate(top_features, 1):
            impact_direction = "INCREASES" if impact > 0 else "DECREASES"
            feature_readable = feature.replace('_', ' ').title()
            narrative += f"""
        {i}. {feature_readable}: {value:.1f}
           - This factor {impact_direction} malware likelihood by {abs(impact):.3f}
           - {'Above' if impact > 0 else 'Below'} normal threshold for benign software
        """
        narrative += f"""
        MEDICAL ANALOGY:
        Like a radiologist examining an X-ray, this AI identified subtle patterns that indicate {'infection' if is_malicious else 'healthy tissue'}:
        - Multiple {'symptoms' if is_malicious else 'healthy indicators'} point to the same conclusion
        - The combination of factors creates a {'concerning' if is_malicious else 'reassuring'} diagnostic picture
        - Individual factors might be innocent, but the pattern is {'highly suspicious' if is_malicious else 'consistently normal'}
        RECOMMENDED ACTION:
        {'Quarantine immediately and conduct detailed forensic analysis' if is_malicious else 'Continue normal operations with routine monitoring'}
        CONFIDENCE ASSESSMENT:
        {'High confidence - multiple strong indicators align' if confidence_level > 0.8 else 'Moderate confidence - some uncertainty remains, consider additional analysis'}
        """
        return narrative.strip()
    def create_regulatory_compliance_matrix(self):
        matrix = {
            'GDPR': {
                'explanation_required': True,
                'automated_decision_threshold': 'High impact on individuals',
                'explanation_detail': 'Meaningful information about logic',
                'right_to_explanation': True,
                'human_review_required': True
            },
            'AI_Bill_of_Rights': {
                'explanation_required': True,
                'notice_required': True,
                'human_alternatives': True,
                'explanation_detail': 'Clear, timely, understandable',
                'fallback_options': True
            },
            'NIST_AI_RMF': {
                'transparency_required': True,
                'explainability_principles': ['Explanation', 'Meaningfulness', 'Accuracy', 'Knowledge limits'],
                'documentation_required': True,
                'testing_required': True
            },
            'SOX': {
                'audit_trail_required': True,
                'decision_documentation': True,
                'control_effectiveness': True,
                'explanation_detail': 'Sufficient for audit purposes'
            },
            'PCI_DSS': {
                'fraud_detection_explanations': True,
                'automated_decision_review': True,
                'false_positive_minimization': True,
                'explanation_detail': 'Technical and business rationale'
            }
        }
        return matrix
    def assess_compliance_readiness(self, explanation_capabilities, regulations):
        compliance_matrix = self.create_regulatory_compliance_matrix()
        readiness_report = {}
        for regulation in regulations:
            if regulation not in compliance_matrix:
                continue
            requirements = compliance_matrix[regulation]
            readiness = {}
            # Add further logic as needed
        return readiness_report
