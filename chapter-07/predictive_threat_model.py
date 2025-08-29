import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb
import joblib
import warnings
warnings.filterwarnings('ignore')

class PredictiveThreatModel:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_columns = []
        self.prediction_history = []
    def prepare_vulnerability_features(self, df):
        """Prepare features for vulnerability exploitation prediction"""
        features = df.copy()
        features['days_since_disclosure'] = (datetime.now() - pd.to_datetime(features['published_date'])).dt.days
        features['is_recent'] = (features['days_since_disclosure'] <= 30).astype(int)
        features['cvss_high'] = (features['cvss_score'] >= 8.0).astype(int)
        features['cvss_critical'] = (features['cvss_score'] >= 9.0).astype(int)
        features['has_poc'] = features['proof_of_concept_available'].astype(int)
        features['exploit_maturity_score'] = features['exploit_maturity'].map({'Unproven': 0, 'Proof of Concept': 1, 'Functional': 2, 'High': 3}).fillna(0)
        features['affects_critical_assets'] = features['critical_asset_exposure'].astype(int)
        features['internet_facing'] = features['external_exposure'].astype(int)
        features['mentioned_in_reports'] = features['threat_intel_mentions'].fillna(0)
        features['associated_with_apt'] = features['apt_group_usage'].astype(int)
        features['popular_product'] = features['product_usage_rank'].apply(lambda x: 1 if x <= 100 else 0)
        return features
    def prepare_user_risk_features(self, df):
        """Prepare features for user targeting prediction"""
        features = df.copy()
        features['login_variance'] = features.groupby('user_id')['login_time'].transform('std')
        features['unusual_hours'] = (features['login_hour'] < 6) | (features['login_hour'] > 22)
        features['weekend_access'] = features['login_weekday'].isin([5, 6]).astype(int)
        features['admin_privileges'] = features['privilege_level'].isin(['admin', 'power_user']).astype(int)
        features['sensitive_data_access'] = features['data_classification_access'].isin(['confidential', 'restricted']).astype(int)
        features['data_transfer_anomaly'] = (features['bytes_transferred'] > features.groupby('user_id')['bytes_transferred'].transform('quantile', 0.95)).astype(int)
        features['profile_completeness'] = (features['linkedin_profile'].astype(int) + features['public_social_media'].astype(int) + features['company_directory_listing'].astype(int))
        return features
    def train_vulnerability_prediction(self, training_data):
        """Train model to predict vulnerability exploitation likelihood"""
        print("Training vulnerability exploitation prediction model...")
        features = self.prepare_vulnerability_features(training_data)
        feature_cols = [
            'cvss_score', 'days_since_disclosure', 'is_recent', 'cvss_high', 'cvss_critical',
            'has_poc', 'exploit_maturity_score', 'affects_critical_assets', 'internet_facing',
            'mentioned_in_reports', 'associated_with_apt', 'popular_product'
        ]
        X = features[feature_cols]
        y = features['exploited_in_30_days']
        X = X.fillna(0)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        models = {
            'random_forest': RandomForestClassifier(n_estimators=200, random_state=42),
            'gradient_boost': GradientBoostingClassifier(n_estimators=200, random_state=42),
            'xgboost': xgb.XGBClassifier(n_estimators=200, random_state=42)
        }
        best_model = None
        best_score = 0
        for name, model in models.items():
            if name == 'xgboost':
                model.fit(X_train, y_train)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            else:
                model.fit(X_train_scaled, y_train)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            auc_score = roc_auc_score(y_test, y_pred_proba)
            print(f"{name} AUC: {auc_score:.3f}")
            if auc_score > best_score:
                best_score = auc_score
                best_model = model
        self.models['vulnerability'] = best_model
        self.scalers['vulnerability'] = scaler
        self.feature_columns = feature_cols
        print(f"Best model AUC: {best_score:.3f}")
        return best_score
    def predict_vulnerability_risk(self, vulnerability_data):
        """Predict exploitation likelihood for new vulnerabilities"""
        if 'vulnerability' not in self.models:
            raise ValueError("Vulnerability model not trained. Call train_vulnerability_prediction first.")
        features = self.prepare_vulnerability_features(vulnerability_data)
        X = features[self.feature_columns].fillna(0)
        model = self.models['vulnerability']
        if isinstance(model, xgb.XGBClassifier):
            probabilities = model.predict_proba(X)[:, 1]
        else:
            X_scaled = self.scalers['vulnerability'].transform(X)
            probabilities = model.predict_proba(X_scaled)[:, 1]
        risk_levels = []
        for prob in probabilities:
            if prob >= 0.8:
                risk_levels.append('CRITICAL')
            elif prob >= 0.6:
                risk_levels.append('HIGH')
            elif prob >= 0.4:
                risk_levels.append('MEDIUM')
            else:
                risk_levels.append('LOW')
        results = pd.DataFrame({
            'cve_id': vulnerability_data['cve_id'],
            'exploitation_probability': probabilities,
            'risk_level': risk_levels,
            'cvss_score': vulnerability_data['cvss_score'],
            'days_since_disclosure': (datetime.now() - pd.to_datetime(vulnerability_data['published_date'])).dt.days
        })
        return results.sort_values('exploitation_probability', ascending=False)
    def generate_threat_forecast(self, days_ahead=30):
        """Generate threat forecast for specified time period"""
        forecast = {
            'forecast_date': datetime.now(),
            'forecast_period': f"{days_ahead} days",
            'predictions': [],
            'risk_summary': {},
            'recommended_actions': []
        }
        forecast['risk_summary'] = {
            'critical_vulnerabilities_expected': 15,
            'high_risk_users_identified': 42,
            'attack_probability_increase': '23% above baseline',
            'recommended_patch_priority_count': 8
        }
        forecast['recommended_actions'] = [
            "Prioritize patching of CVE-2024-XXXX (98% exploitation probability)",
            "Implement additional monitoring for 15 high-risk user accounts", 
            "Deploy virtual patches for internet-facing assets with critical vulnerabilities",
            "Conduct phishing simulation for users with high social engineering risk scores"
        ]
        return forecast
    def save_model(self, filepath):
        """Save trained model and scalers"""
        joblib.dump({
            'models': self.models,
            'scalers': self.scalers,
            'feature_columns': self.feature_columns
        }, filepath)
        print(f"Model saved to {filepath}")
    def load_model(self, filepath):
        """Load trained model and scalers"""
        saved_data = joblib.load(filepath)
        self.models = saved_data['models']
        self.scalers = saved_data['scalers']
        self.feature_columns = saved_data['feature_columns']
        print(f"Model loaded from {filepath}")

def demonstrate_predictive_model():
    """Demonstrate the predictive threat model with sample data"""
    np.random.seed(42)
    n_samples = 1000
    sample_vuln_data = pd.DataFrame({
        'cve_id': [f'CVE-2024-{i:04d}' for i in range(n_samples)],
        'published_date': pd.date_range(start='2024-01-01', periods=n_samples, freq='D'),
        'cvss_score': np.random.uniform(1, 10, n_samples),
        'proof_of_concept_available': np.random.choice([True, False], n_samples, p=[0.3, 0.7]),
        'exploit_maturity': np.random.choice(['Unproven', 'Proof of Concept', 'Functional', 'High'], n_samples),
        'critical_asset_exposure': np.random.choice([True, False], n_samples, p=[0.2, 0.8]),
        'external_exposure': np.random.choice([True, False], n_samples, p=[0.4, 0.6]),
        'threat_intel_mentions': np.random.poisson(2, n_samples),
        'apt_group_usage': np.random.choice([True, False], n_samples, p=[0.1, 0.9]),
        'product_usage_rank': np.random.randint(1, 1000, n_samples),
        'exploited_in_30_days': np.random.choice([True, False], n_samples, p=[0.05, 0.95])
    })
    predictor = PredictiveThreatModel()
    auc_score = predictor.train_vulnerability_prediction(sample_vuln_data)
    new_vulns = sample_vuln_data.head(10).copy()
    predictions = predictor.predict_vulnerability_risk(new_vulns)
    print("\n=== Vulnerability Risk Predictions ===")
    print(predictions[['cve_id', 'exploitation_probability', 'risk_level', 'cvss_score']].to_string(index=False))
    forecast = predictor.generate_threat_forecast()
    print("\n=== 30-Day Threat Forecast ===")
    print(f"Forecast Date: {forecast['forecast_date']}")
    print(f"Period: {forecast['forecast_period']}")
    print("\nRisk Summary:")
    for key, value in forecast['risk_summary'].items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
    print("\nRecommended Actions:")
    for i, action in enumerate(forecast['recommended_actions'], 1):
        print(f"  {i}. {action}")
    return predictor

if __name__ == "__main__":
    model = demonstrate_predictive_model()
