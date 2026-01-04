"""
Machine Learning-Based Vulnerability Detector
Uses ML models to detect vulnerabilities in web applications
"""

import asyncio
import aiohttp
import json
import re
from typing import List, Dict, Any
import numpy as np
from loguru import logger

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    TfidfVectorizer, RandomForestClassifier, IsolationForest, train_test_split, classification_report, StandardScaler, joblib = None, None, None, None, None, None, None

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense, Dropout, LSTM
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf, Sequential, Dense, Dropout, LSTM, Tokenizer, pad_sequences = None, None, None, None, None, None, None


class MLDetector:
    """Machine learning-based vulnerability detector"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.models = {}
        self.vectorizers = {}
        self.tokenizers = {}
        
        # Initialize models if dependencies are available
        if SKLEARN_AVAILABLE:
            self._initialize_sklearn_models()
        
        if TENSORFLOW_AVAILABLE:
            self._initialize_tensorflow_models()
    
    def _initialize_sklearn_models(self):
        """Initialize scikit-learn based models with enhanced capabilities"""
        try:
            # SQL Injection detection model
            self.models['sql_injection'] = RandomForestClassifier(n_estimators=200, random_state=42, max_depth=10)
            self.vectorizers['sql_injection'] = TfidfVectorizer(max_features=2000, ngram_range=(1, 4))
            
            # XSS detection model
            self.models['xss'] = RandomForestClassifier(n_estimators=200, random_state=42, max_depth=10)
            self.vectorizers['xss'] = TfidfVectorizer(max_features=2000, ngram_range=(1, 4))
            
            # Directory traversal detection model
            self.models['lfi'] = RandomForestClassifier(n_estimators=200, random_state=42, max_depth=10)
            self.vectorizers['lfi'] = TfidfVectorizer(max_features=2000, ngram_range=(1, 4))
            
            # Anomaly detection model
            self.models['anomaly'] = IsolationForest(contamination=0.1, random_state=42)
            self.scalers = {}
            
            logger.info("Enhanced scikit-learn models initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize enhanced scikit-learn models: {e}")
    
    def _initialize_tensorflow_models(self):
        """Initialize TensorFlow based models"""
        try:
            # Simple neural network for vulnerability detection
            model = Sequential([
                Dense(128, activation='relu', input_shape=(1000,)),
                Dropout(0.5),
                Dense(64, activation='relu'),
                Dropout(0.5),
                Dense(32, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            
            self.models['neural'] = model
            self.tokenizers['neural'] = Tokenizer(num_words=10000)
            
            logger.info("TensorFlow models initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize TensorFlow models: {e}")
    
    async def train_models(self, training_data: List[Dict[str, Any]]) -> None:
        """
        Train ML models with provided training data
        Training data format: [{'text': 'request content', 'label': 'vulnerability_type'}, ...]
        """
        if not SKLEARN_AVAILABLE and not TENSORFLOW_AVAILABLE:
            logger.warning("ML dependencies not available, skipping training")
            return
        
        logger.info("Training ML models...")
        
        try:
            # Prepare training data by vulnerability type
            sql_data = [(item['text'], 1 if item['label'] == 'sql_injection' else 0) for item in training_data]
            xss_data = [(item['text'], 1 if item['label'] == 'xss' else 0) for item in training_data]
            lfi_data = [(item['text'], 1 if item['label'] == 'lfi' else 0) for item in training_data]
            
            # Train SQL injection model
            if sql_data and 'sql_injection' in self.models:
                texts, labels = zip(*sql_data)
                X = self.vectorizers['sql_injection'].fit_transform(texts)
                self.models['sql_injection'].fit(X, labels)
                logger.info("SQL injection model trained")
            
            # Train XSS model
            if xss_data and 'xss' in self.models:
                texts, labels = zip(*xss_data)
                X = self.vectorizers['xss'].fit_transform(texts)
                self.models['xss'].fit(X, labels)
                logger.info("XSS model trained")
            
            # Train LFI model
            if lfi_data and 'lfi' in self.models:
                texts, labels = zip(*lfi_data)
                X = self.vectorizers['lfi'].fit_transform(texts)
                self.models['lfi'].fit(X, labels)
                logger.info("LFI model trained")
            
            logger.success("All ML models trained successfully")
        except Exception as e:
            logger.error(f"ML model training failed: {e}")
    
    async def detect_vulnerabilities(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities using ML models
        """
        if not self.models:
            logger.warning("No trained models available, skipping ML detection")
            return []
        
        logger.info(f"Running ML-based vulnerability detection on {len(targets)} targets")
        
        vulnerabilities = []
        
        for target in targets:
            try:
                # Extract features from target
                features = await self._extract_features(target)
                
                # Run ML detection
                ml_results = await self._run_ml_detection(features)
                vulnerabilities.extend(ml_results)
                
            except Exception as e:
                logger.debug(f"ML detection failed for {target}: {e}")
        
        logger.success(f"ML detection completed: {len(vulnerabilities)} potential vulnerabilities found")
        return vulnerabilities
    
    async def _extract_features(self, target: str) -> Dict[str, Any]:
        """
        Extract features from target for ML analysis
        """
        features = {
            'url': target,
            'content': '',
            'headers': {},
            'response_time': 0,
            'status_code': 0
        }
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(target, ssl=False) as response:
                    features['content'] = await response.text()
                    features['headers'] = dict(response.headers)
                    features['status_code'] = response.status
                    features['response_time'] = response.headers.get('Server-Timing', 0)
        except Exception as e:
            logger.debug(f"Feature extraction failed for {target}: {e}")
        
        return features
    
    async def _run_ml_detection(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Run ML detection on extracted features
        """
        vulnerabilities = []
        
        try:
            content = features.get('content', '')
            
            # Traditional ML detection
            # SQL Injection detection
            if 'sql_injection' in self.models and content:
                prediction = await self._predict_vulnerability('sql_injection', content)
                if prediction > 0.7:  # Threshold for positive detection
                    vulnerabilities.append({
                        'id': f'ml-sqli-{hash(features["url"])}',
                        'name': 'ML-Detected SQL Injection',
                        'severity': 'high',
                        'cvss_score': 8.5,
                        'cve_id': 'CWE-89',
                        'url': features['url'],
                        'description': 'Machine learning model detected potential SQL injection vulnerability with high confidence.',
                        'confidence': prediction,
                        'solution': 'Review input validation and use parameterized queries.',
                        'tool': 'MLDetector-Pro'
                    })
            
            # XSS detection
            if 'xss' in self.models and content:
                prediction = await self._predict_vulnerability('xss', content)
                if prediction > 0.7:
                    vulnerabilities.append({
                        'id': f'ml-xss-{hash(features["url"])}',
                        'name': 'ML-Detected XSS',
                        'severity': 'high',
                        'cvss_score': 7.5,
                        'cve_id': 'CWE-79',
                        'url': features['url'],
                        'description': 'Machine learning model detected potential XSS vulnerability with high confidence.',
                        'confidence': prediction,
                        'solution': 'Implement proper input sanitization and output encoding.',
                        'tool': 'MLDetector-Pro'
                    })
            
            # Directory traversal detection
            if 'lfi' in self.models and content:
                prediction = await self._predict_vulnerability('lfi', content)
                if prediction > 0.7:
                    vulnerabilities.append({
                        'id': f'ml-lfi-{hash(features["url"])}',
                        'name': 'ML-Detected Directory Traversal',
                        'severity': 'high',
                        'cvss_score': 8.0,
                        'cve_id': 'CWE-22',
                        'url': features['url'],
                        'description': 'Machine learning model detected potential directory traversal vulnerability with high confidence.',
                        'confidence': prediction,
                        'solution': 'Validate and sanitize all file paths.',
                        'tool': 'MLDetector-Pro'
                    })
            
            # Anomaly detection for hidden vulnerabilities
            await self._detect_anomalies(features, vulnerabilities)
            
        except Exception as e:
            logger.debug(f"ML detection failed: {e}")
        
        return vulnerabilities
    
    async def _detect_anomalies(self, features: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]):
        """Detect anomalies that may indicate hidden vulnerabilities"""
        try:
            # Extract numerical features for anomaly detection
            feature_vector = []
            
            # Response time anomaly
            response_time = features.get('response_time', 0)
            if response_time:
                feature_vector.append(float(response_time))
            
            # Status code anomaly
            status_code = features.get('status_code', 0)
            feature_vector.append(status_code)
            
            # Content length anomaly
            content = features.get('content', '')
            content_length = len(content)
            feature_vector.append(content_length)
            
            # Header count anomaly
            headers = features.get('headers', {})
            header_count = len(headers)
            feature_vector.append(header_count)
            
            # If we have enough features, run anomaly detection
            if len(feature_vector) >= 4 and 'anomaly' in self.models:
                # Reshape for sklearn
                X = np.array(feature_vector).reshape(1, -1)
                
                # Scale features if scaler is available
                if 'anomaly' in self.scalers:
                    X = self.scalers['anomaly'].transform(X)
                
                # Predict anomaly
                anomaly_score = self.models['anomaly'].decision_function(X)[0]
                
                # If anomaly score is below threshold, it's an anomaly
                if anomaly_score < 0:
                    vulnerabilities.append({
                        'id': f'anomaly-{hash(features["url"])}',
                        'name': 'Behavioral Anomaly Detected',
                        'severity': 'medium',
                        'cvss_score': 5.0,
                        'url': features['url'],
                        'description': f'Unusual behavioral pattern detected (anomaly score: {anomaly_score:.2f}). This may indicate a hidden vulnerability or misconfiguration.',
                        'anomaly_score': anomaly_score,
                        'solution': 'Investigate the unusual behavior. Check for hidden functionality or misconfigurations.',
                        'tool': 'MLDetector-Anomaly'
                    })
                    logger.info(f"ℹ️  Behavioral anomaly detected: {features['url']} (score: {anomaly_score:.2f})")
                    
        except Exception as e:
            logger.debug(f"Anomaly detection failed: {e}")
    
    async def _predict_vulnerability(self, model_name: str, content: str) -> float:
        """
        Predict vulnerability using specific model
        """
        try:
            if model_name in self.models and model_name in self.vectorizers:
                # Transform content using fitted vectorizer
                X = self.vectorizers[model_name].transform([content])
                
                # Get prediction probability
                if hasattr(self.models[model_name], 'predict_proba'):
                    proba = self.models[model_name].predict_proba(X)
                    return float(proba[0][1]) if len(proba[0]) > 1 else 0.0
                else:
                    prediction = self.models[model_name].predict(X)
                    return float(prediction[0]) if isinstance(prediction[0], (int, float)) else 0.0
            
            return 0.0
        except Exception as e:
            logger.debug(f"Prediction failed for {model_name}: {e}")
            return 0.0
    
    def save_models(self, model_path: str) -> None:
        """
        Save trained models to disk
        """
        try:
            if SKLEARN_AVAILABLE:
                for model_name, model in self.models.items():
                    if model_name != 'neural':  # Skip TensorFlow model
                        joblib.dump(model, f"{model_path}_{model_name}_model.pkl")
                        joblib.dump(self.vectorizers.get(model_name), f"{model_path}_{model_name}_vectorizer.pkl")
            
            logger.success(f"Models saved to {model_path}")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def load_models(self, model_path: str) -> None:
        """
        Load trained models from disk
        """
        try:
            if SKLEARN_AVAILABLE:
                model_types = ['sql_injection', 'xss', 'lfi']
                for model_type in model_types:
                    try:
                        self.models[model_type] = joblib.load(f"{model_path}_{model_type}_model.pkl")
                        self.vectorizers[model_type] = joblib.load(f"{model_path}_{model_type}_vectorizer.pkl")
                    except FileNotFoundError:
                        continue
            
            logger.success(f"Models loaded from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load models: {e}")

# Example usage and training data
def get_sample_training_data() -> List[Dict[str, Any]]:
    """
    Sample training data for demonstration
    In practice, this would come from a larger dataset
    """
    return [
        {
            'text': "SELECT * FROM users WHERE id = '1' OR '1'='1'",
            'label': 'sql_injection'
        },
        {
            'text': "<script>alert('XSS')</script>",
            'label': 'xss'
        },
        {
            'text': "../../../etc/passwd",
            'label': 'lfi'
        },
        {
            'text': "Normal user input without malicious content",
            'label': 'clean'
        },
        {
            'text': "DROP TABLE users; --",
            'label': 'sql_injection'
        },
        {
            'text': "<img src=x onerror=alert(1)>",
            'label': 'xss'
        }
    ]

# Example usage
if __name__ == "__main__":
    async def main():
        detector = MLDetector()
        
        # Train models with sample data
        training_data = get_sample_training_data()
        await detector.train_models(training_data)
        
        # Save models
        detector.save_models("./models/ml_detector")
        
        # Detect vulnerabilities
        targets = ["http://example.com"]
        results = await detector.detect_vulnerabilities(targets)
        print(f"Found {len(results)} potential vulnerabilities")
    
    # asyncio.run(main())