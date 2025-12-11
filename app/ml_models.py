"""
Machine Learning Models for Threat Detection
AI-powered anomaly detection and threat classification
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from typing import Dict, List, Tuple
import joblib
from datetime import datetime

class AnomalyDetector:
    """
    AI-powered anomaly detection using Isolation Forest and statistical methods
    """
    
    def __init__(self, contamination=0.1):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def train(self, normal_data: pd.DataFrame) -> Dict:
        """
        Train anomaly detection model on normal behavior data
        
        Args:
            normal_data: DataFrame with normal network/user behavior
        
        Returns:
            Training metrics
        """
        # Prepare features
        X = self._prepare_features(normal_data)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        self.is_trained = True
        
        # Calculate training metrics
        predictions = self.model.predict(X_scaled)
        anomaly_count = np.sum(predictions == -1)
        
        return {
            'samples_trained': len(X),
            'anomalies_in_training': anomaly_count,
            'contamination_rate': self.contamination,
            'training_time': datetime.now().isoformat(),
            'model_type': 'Isolation Forest'
        }
    
    def detect(self, data: pd.DataFrame) -> Dict:
        """
        Detect anomalies in new data
        
        Args:
            data: DataFrame with network/user behavior to analyze
        
        Returns:
            Detection results with anomaly scores
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before detection")
        
        # Prepare features
        X = self._prepare_features(data)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict anomalies
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        # Normalize scores to 0-100 range
        normalized_scores = self._normalize_scores(anomaly_scores)
        
        # Identify anomalies
        anomaly_indices = np.where(predictions == -1)[0]
        
        anomalies = []
        for idx in anomaly_indices:
            anomalies.append({
                'index': int(idx),
                'anomaly_score': float(normalized_scores[idx]),
                'severity': self._score_to_severity(float(normalized_scores[idx])),
                'timestamp': data.iloc[idx].get('timestamp', datetime.now()).isoformat() if 'timestamp' in data.columns else datetime.now().isoformat()
            })
        
        return {
            'total_samples': len(data),
            'anomalies_detected': len(anomalies),
            'anomaly_rate': len(anomalies) / len(data) if len(data) > 0 else 0,
            'anomalies': anomalies,
            'detection_time': datetime.now().isoformat()
        }
    
    def _prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """Extract and prepare features for model"""
        features = []
        
        # Network traffic features
        if 'bytes_sent' in data.columns:
            features.append(data['bytes_sent'].values)
        if 'bytes_received' in data.columns:
            features.append(data['bytes_received'].values)
        if 'packet_count' in data.columns:
            features.append(data['packet_count'].values)
        if 'connection_duration' in data.columns:
            features.append(data['connection_duration'].values)
        
        # If no specific features, create synthetic ones
        if len(features) == 0:
            features = [
                np.random.randn(len(data)),
                np.random.randn(len(data)),
                np.random.randn(len(data))
            ]
        
        return np.column_stack(features)
    
    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Normalize anomaly scores to 0-100 range"""
        min_score = scores.min()
        max_score = scores.max()
        
        if max_score == min_score:
            return np.zeros_like(scores)
        
        normalized = 100 * (scores - min_score) / (max_score - min_score)
        return normalized
    
    def _score_to_severity(self, score: float) -> str:
        """Convert anomaly score to severity level"""
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        else:
            return 'Low'
    
    def save_model(self, filepath: str):
        """Save trained model to disk"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }, filepath)
    
    def load_model(self, filepath: str):
        """Load trained model from disk"""
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_trained = data['is_trained']


class ThreatClassifier:
    """
    Multi-class threat classification using Random Forest
    """
    
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            random_state=42,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.threat_classes = [
            'Malware',
            'Phishing',
            'DDoS',
            'Intrusion',
            'Data Exfiltration',
            'Credential Theft',
            'Ransomware'
        ]
        
    def train(self, X_train: pd.DataFrame, y_train: pd.Series) -> Dict:
        """
        Train threat classification model
        
        Args:
            X_train: Training features
            y_train: Training labels (threat types)
        
        Returns:
            Training metrics
        """
        # Scale features
        X_scaled = self.scaler.fit_transform(X_train)
        
        # Train model
        self.model.fit(X_scaled, y_train)
        self.is_trained = True
        
        # Calculate training accuracy
        train_accuracy = self.model.score(X_scaled, y_train)
        
        # Feature importance
        feature_importance = self.model.feature_importances_
        
        return {
            'samples_trained': len(X_train),
            'num_classes': len(np.unique(y_train)),
            'training_accuracy': float(train_accuracy),
            'feature_importance': feature_importance.tolist(),
            'training_time': datetime.now().isoformat(),
            'model_type': 'Random Forest Classifier'
        }
    
    def classify(self, X: pd.DataFrame) -> Dict:
        """
        Classify threats in new data
        
        Args:
            X: Features to classify
        
        Returns:
            Classification results with probabilities
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before classification")
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict classes and probabilities
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        results = []
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            # Get top 3 most likely threat types
            top_indices = np.argsort(probs)[-3:][::-1]
            top_threats = [
                {
                    'threat_type': self.model.classes_[idx],
                    'probability': float(probs[idx])
                }
                for idx in top_indices
            ]
            
            results.append({
                'index': i,
                'predicted_threat': pred,
                'confidence': float(probs.max()),
                'top_threats': top_threats,
                'severity': self._threat_to_severity(pred)
            })
        
        return {
            'total_classified': len(X),
            'classifications': results,
            'classification_time': datetime.now().isoformat()
        }
    
    def _threat_to_severity(self, threat_type: str) -> str:
        """Map threat type to severity level"""
        critical_threats = ['Ransomware', 'Data Exfiltration', 'Credential Theft']
        high_threats = ['Malware', 'Intrusion']
        
        if threat_type in critical_threats:
            return 'Critical'
        elif threat_type in high_threats:
            return 'High'
        else:
            return 'Medium'
    
    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict:
        """
        Evaluate model performance on test data
        
        Args:
            X_test: Test features
            y_test: True labels
        
        Returns:
            Evaluation metrics
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        # Scale features
        X_scaled = self.scaler.transform(X_test)
        
        # Predictions
        predictions = self.model.predict(X_scaled)
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(y_test, predictions, average='weighted')
        recall = recall_score(y_test, predictions, average='weighted')
        f1 = f1_score(y_test, predictions, average='weighted')
        
        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'test_samples': len(X_test),
            'evaluation_time': datetime.now().isoformat()
        }
    
    def save_model(self, filepath: str):
        """Save trained model to disk"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained,
            'threat_classes': self.threat_classes
        }, filepath)
    
    def load_model(self, filepath: str):
        """Load trained model from disk"""
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_trained = data['is_trained']
        self.threat_classes = data['threat_classes']


class BehaviorAnalyzer:
    """
    User and Entity Behavior Analytics (UEBA)
    """
    
    def __init__(self):
        self.baseline_profiles = {}
        
    def create_baseline(self, user_id: str, activity_data: pd.DataFrame) -> Dict:
        """
        Create baseline behavior profile for a user
        
        Args:
            user_id: User identifier
            activity_data: Historical activity data
        
        Returns:
            Baseline profile
        """
        profile = {
            'user_id': user_id,
            'avg_login_time': activity_data['login_hour'].mean() if 'login_hour' in activity_data.columns else 12,
            'avg_session_duration': activity_data['session_duration'].mean() if 'session_duration' in activity_data.columns else 60,
            'common_locations': activity_data['location'].mode().tolist() if 'location' in activity_data.columns else [],
            'avg_data_transfer': activity_data['data_transferred'].mean() if 'data_transferred' in activity_data.columns else 1000,
            'typical_resources': activity_data['resource'].value_counts().head(10).to_dict() if 'resource' in activity_data.columns else {},
            'created_at': datetime.now().isoformat()
        }
        
        self.baseline_profiles[user_id] = profile
        return profile
    
    def detect_deviation(self, user_id: str, current_activity: Dict) -> Dict:
        """
        Detect deviations from baseline behavior
        
        Args:
            user_id: User identifier
            current_activity: Current activity to analyze
        
        Returns:
            Deviation analysis
        """
        if user_id not in self.baseline_profiles:
            return {
                'error': 'No baseline profile found for user',
                'user_id': user_id
            }
        
        baseline = self.baseline_profiles[user_id]
        deviations = []
        risk_score = 0
        
        # Check login time deviation
        if 'login_hour' in current_activity:
            time_diff = abs(current_activity['login_hour'] - baseline['avg_login_time'])
            if time_diff > 6:  # More than 6 hours difference
                deviations.append({
                    'type': 'Unusual Login Time',
                    'severity': 'Medium',
                    'details': f'Login at {current_activity["login_hour"]}:00, typical: {baseline["avg_login_time"]:.0f}:00'
                })
                risk_score += 25
        
        # Check location deviation
        if 'location' in current_activity and current_activity['location'] not in baseline['common_locations']:
            deviations.append({
                'type': 'Unusual Location',
                'severity': 'High',
                'details': f'Access from {current_activity["location"]}, not in typical locations'
            })
            risk_score += 35
        
        # Check data transfer deviation
        if 'data_transferred' in current_activity:
            if current_activity['data_transferred'] > baseline['avg_data_transfer'] * 3:
                deviations.append({
                    'type': 'Excessive Data Transfer',
                    'severity': 'Critical',
                    'details': f'Transferred {current_activity["data_transferred"]} bytes, typical: {baseline["avg_data_transfer"]:.0f}'
                })
                risk_score += 40
        
        return {
            'user_id': user_id,
            'deviations_detected': len(deviations),
            'deviations': deviations,
            'risk_score': min(risk_score, 100),
            'severity': 'Critical' if risk_score >= 70 else 'High' if risk_score >= 40 else 'Medium' if risk_score >= 20 else 'Low',
            'analysis_time': datetime.now().isoformat()
        }
