"""
Intelligent Threat Detection Module for Quantum-Resistant Encryption System
Monitors cryptographic operations and detects anomalous or potentially malicious behavior in real-time.

This module implements:
- Continuous monitoring of encryption/decryption operations
- Security event logging (failed operations, integrity failures, etc.)
- AI-based anomaly detection using Isolation Forest and statistical analysis
- Dynamic risk scoring per user/session
- Explainable threat classification (Low, Medium, High)
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
import json
import os
from typing import List, Dict, Optional, Tuple, Deque
from collections import defaultdict, deque


class ThreatDetection:
    """
    Intelligent threat detection system for quantum-resistant encryption operations.
    
    Monitors and analyzes:
    - Failed Kyber decapsulation attempts
    - Repeated AES decryption failures
    - Ciphertext modification or integrity failures
    - Abnormal request frequency
    - Reuse of initialization vectors (IVs)
    - Key mismatch events
    - Sudden spikes in data size or usage volume
    """
    
    def __init__(self):
        """Initialize threat detection with ML models and tracking structures."""
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.activity_log: Deque[Dict] = deque(maxlen=10000)
        self.security_events: Deque[Dict] = deque(maxlen=2000)
        self.user_sessions: Dict[str, Dict] = defaultdict(lambda: {
            'risk_score': 0.0,
            'failed_operations': 0,
            'last_activity': None,
            'operation_count': 0,
            'iv_history': set(),
            'recent_ivs': deque(maxlen=1000)
        })
        self.manual_blocklist = set()
        self.model_trained = False
        
        # Statistical thresholds
        self.thresholds = {
            'max_failures_per_minute': 5,
            'max_operations_per_minute': 20,
            'large_file_threshold': 100 * 1024 * 1024,  # 100MB
            'spike_multiplier': 3.0,  # 3x normal volume
            'iv_reuse_threshold': 1,  # Any IV reuse is suspicious
            'key_mismatch_threshold': 2  # 2+ key mismatches
        }
    
    def log_activity(self, activity_type: str, file_size: int = 0, 
                    success: bool = True, user_id: Optional[str] = None,
                    algorithm: Optional[str] = None, 
                    event_type: Optional[str] = None,
                    iv: Optional[str] = None,
                    integrity_check: Optional[bool] = None,
                    key_mismatch: bool = False,
                    **kwargs) -> None:
        """
        Log an encryption/decryption activity for analysis.
        
        Args:
            activity_type: Type of activity ('encrypt' or 'decrypt')
            file_size: Size of the file/entity processed (bytes)
            success: Whether the operation succeeded
            user_id: Optional user identifier
            algorithm: Algorithm used ('kyber512', 'kyber768', 'aes256')
            event_type: Specific event type ('kyber_decapsulation_failed', 'aes_decrypt_failed', 
                         'integrity_failure', 'iv_reuse', 'key_mismatch', etc.)
            iv: Initialization vector used (for IV reuse detection)
            integrity_check: Whether integrity check passed
            key_mismatch: Whether key mismatch occurred
            **kwargs: Additional metadata
        """
        timestamp = datetime.now()
        user_id = user_id or 'anonymous'
        
        # Create activity record
        activity = {
            'timestamp': timestamp.isoformat(),
            'activity_type': activity_type,
            'file_size': file_size,
            'success': success,
            'user_id': user_id,
            'algorithm': algorithm or 'unknown',
            'hour': timestamp.hour,
            'day_of_week': timestamp.weekday(),
            'event_type': event_type,
            'iv': iv,
            'integrity_check': integrity_check,
            'key_mismatch': key_mismatch,
            **kwargs
        }
        
        self.activity_log.append(activity)
        
        # Prevent memory exhaustion during IP-spoofing DoS attacks
        if len(self.user_sessions) > 10000:
            self._cleanup_old_sessions()
            
        # Update user session tracking
        session = self.user_sessions[user_id]
        session['last_activity'] = timestamp
        session['operation_count'] += 1
        
        # Track IV reuse
        if iv:
            if iv in session['recent_ivs']:
                # IV reuse detected
                self._log_security_event(user_id, 'iv_reuse', {
                    'iv': iv,
                    'activity_type': activity_type,
                    'algorithm': algorithm
                }, severity='high')
            session['recent_ivs'].append(iv)
        
        # Track failed operations
        if not success:
            session['failed_operations'] += 1
            event_type = event_type or self._infer_event_type(activity_type, algorithm)
            self._log_security_event(user_id, event_type, {
                'activity_type': activity_type,
                'algorithm': algorithm,
                'file_size': file_size
            })
        
        # Track integrity failures
        if integrity_check is False:
            self._log_security_event(user_id, 'integrity_failure', {
                'activity_type': activity_type,
                'algorithm': algorithm,
                'file_size': file_size
            }, severity='high')
        
        # Track key mismatches
        if key_mismatch:
            self._log_security_event(user_id, 'key_mismatch', {
                'activity_type': activity_type,
                'algorithm': algorithm
            }, severity='high')
        
        # Update risk score
        self._update_risk_score(user_id, activity)
    
    def _cleanup_old_sessions(self) -> None:
        """Clean up inactive sessions to prevent memory exhaustion during DoS attacks."""
        now = datetime.now()
        # Remove sessions older than 1 hour
        keys_to_remove = [
            uid for uid, session in self.user_sessions.items()
            if session.get('last_activity') and (now - session['last_activity']).total_seconds() > 3600
        ]
        for uid in keys_to_remove:
            del self.user_sessions[uid]
            
        # If still too large (e.g. rapid IP spoofing), keep only the most recent 5000
        if len(self.user_sessions) > 10000:
            sorted_sessions = sorted(
                [(uid, s) for uid, s in self.user_sessions.items() if s.get('last_activity')],
                key=lambda x: x[1]['last_activity'],
                reverse=True
            )
            # Rebuild dictionary with top 5000
            self.user_sessions.clear()
            for uid, s in sorted_sessions[:5000]:
                self.user_sessions[uid] = s
    
    def _infer_event_type(self, activity_type: str, algorithm: Optional[str]) -> str:
        """Infer event type from activity and algorithm."""
        if activity_type == 'decrypt':
            if algorithm and 'kyber' in algorithm.lower():
                return 'kyber_decapsulation_failed'
            elif algorithm and 'aes' in algorithm.lower():
                return 'aes_decrypt_failed'
        return 'operation_failed'
    
    def _log_security_event(self, user_id: str, event_type: str, 
                           details: Dict, severity: str = 'medium') -> None:
        """Log a security-relevant event."""
        event = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'event_type': event_type,
            'severity': severity,
            'details': details
        }
        self.security_events.append(event)
    
    def _update_risk_score(self, user_id: str, activity: Dict) -> None:
        """Update dynamic risk score for a user/session."""
        session = self.user_sessions[user_id]
        risk_delta = 0.0
        
        # Failed operations increment risk
        if not activity.get('success', True):
            risk_delta += 5.0
        
        # Integrity failures heavily increase risk
        if activity.get('integrity_check') is False:
            risk_delta += 25.0
        
        # Key mismatches heavily increase risk
        if activity.get('key_mismatch', False):
            risk_delta += 20.0
        
        # Large file spikes
        if activity.get('file_size', 0) > self.thresholds['large_file_threshold']:
            risk_delta += 3.0
        
        # Check for abnormal frequency
        recent_ops = self._count_recent_operations(user_id, minutes=1)
        if recent_ops > self.thresholds['max_operations_per_minute']:
            risk_delta += 2.0 * (recent_ops / self.thresholds['max_operations_per_minute'])
        
        # Check for failure rate
        recent_failures = self._count_recent_failures(user_id, minutes=1)
        if recent_failures > self.thresholds['max_failures_per_minute']:
            risk_delta += 10.0 * (recent_failures / self.thresholds['max_failures_per_minute'])
        
        # Decay risk score over time (half-life of 30 minutes)
        time_since_last = (datetime.now() - session['last_activity']).total_seconds() / 60
        if time_since_last > 0:
            decay_factor = 0.5 ** (time_since_last / 30)
            session['risk_score'] = session['risk_score'] * decay_factor
        
        session['risk_score'] = min(100.0, session['risk_score'] + risk_delta)
    
    def _count_recent_operations(self, user_id: str, minutes: int = 1) -> int:
        """Count operations by user in recent time window."""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return sum(1 for act in self.activity_log 
                   if act.get('user_id') == user_id 
                   and datetime.fromisoformat(act['timestamp']) > cutoff)
    
    def _count_recent_failures(self, user_id: str, minutes: int = 1) -> int:
        """Count failed operations by user in recent time window."""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return sum(1 for act in self.activity_log 
                   if act.get('user_id') == user_id 
                   and not act.get('success', True)
                   and datetime.fromisoformat(act['timestamp']) > cutoff)
    
    def extract_features(self, activities: iter) -> np.ndarray:
        """
        Extract features from activity logs for ML analysis.
        
        Args:
            activities: Iterable of activity dictionaries
            
        Returns:
            Feature matrix as numpy array
        """
        features = []
        
        for activity in activities:
            user_id = activity.get('user_id', 'anonymous')
            session = self.user_sessions[user_id]
            
            feature_vector = [
                activity.get('file_size', 0),
                activity.get('hour', 12),
                activity.get('day_of_week', 3),
                1 if activity.get('activity_type') == 'encrypt' else 0,
                1 if activity.get('success') else 0,
                activity.get('file_size', 0) / (1024 * 1024) if activity.get('file_size', 0) > 0 else 0,
                session['risk_score'],
                session['failed_operations'],
                self._count_recent_operations(user_id, minutes=5),
                self._count_recent_failures(user_id, minutes=5),
                1 if activity.get('integrity_check') is False else 0,
                1 if activity.get('key_mismatch', False) else 0,
            ]
            
            # Add time-based features
            try:
                activities_list = list(activities)
                if len(activities_list) > 1:
                    idx = activities_list.index(activity)
                    if idx > 0:
                        prev_time = datetime.fromisoformat(activities_list[idx - 1]['timestamp'])
                        curr_time = datetime.fromisoformat(activity['timestamp'])
                        time_diff = (curr_time - prev_time).total_seconds()
                        feature_vector.append(time_diff)
                    else:
                        feature_vector.append(0)
                else:
                    feature_vector.append(0)
            except:
                feature_vector.append(0)
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def train_model(self) -> None:
        """Train the threat detection model on logged activities."""
        if len(self.activity_log) < 10:
            # Generate synthetic training data if insufficient logs
            synthetic_data = self._generate_synthetic_data()
            self.activity_log.extend(synthetic_data)
        
        # Extract features
        features = self.extract_features(self.activity_log)
        
        if len(features) > 0:
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Train isolation forest
            self.isolation_forest.fit(features_scaled)
            
            self.model_trained = True
    
    def detect_threats(self, window_size: int = 50) -> List[Dict]:
        """
        Detect potential threats in recent activities using AI and statistical analysis.
        
        Args:
            window_size: Number of recent activities to analyze
            
        Returns:
            List of detected threats with scores, explanations, and recommendations
        """
        threats = []
        
        # Get recent activities
        recent_activities = list(self.activity_log)[-window_size:] if len(self.activity_log) > window_size else list(self.activity_log)
        
        if len(recent_activities) < 5:
            # Use statistical analysis if insufficient data for ML
            return self._statistical_threat_detection(recent_activities)
        
        # Train model if needed
        if not self.model_trained:
            self.train_model()
        
        # Extract features and predict
        features = self.extract_features(recent_activities)
        features_scaled = self.scaler.transform(features)
        anomaly_scores = self.isolation_forest.decision_function(features_scaled)
        predictions = self.isolation_forest.predict(features_scaled)
        
        # Identify threats from ML predictions
        for i, activity in enumerate(recent_activities):
            if predictions[i] == -1:  # Anomaly detected
                user_id = activity.get('user_id', 'anonymous')
                session = self.user_sessions[user_id]
                
                threat = {
                    'threat_id': f"TH-{datetime.now().strftime('%Y%m%d')}-{len(threats)+1:03d}",
                    'timestamp': activity['timestamp'],
                    'user_id': user_id,
                    'activity_type': activity['activity_type'],
                    'algorithm': activity.get('algorithm', 'unknown'),
                    'severity': self._calculate_severity(anomaly_scores[i], activity, session),
                    'risk_score': round(session['risk_score'], 2),
                    'anomaly_score': float(anomaly_scores[i]),
                    'event_type': activity.get('event_type', 'anomalous_pattern'),
                    'explanation': self._generate_explanation(activity, anomaly_scores[i], session),
                    'recommendation': self._generate_recommendation(activity, session),
                    'affected_algorithm': activity.get('algorithm', 'unknown')
                }
                threats.append(threat)
        
        # Add threats from security events
        threats.extend(self._analyze_security_events())
        
        # Sort by severity and risk score
        threats.sort(key=lambda x: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x['severity'], 4),
            -x['risk_score']
        ))
        
        return threats
    
    def _statistical_threat_detection(self, activities: List[Dict]) -> List[Dict]:
        """Use statistical thresholds for threat detection when ML data is insufficient."""
        threats = []
        
        for activity in activities:
            user_id = activity.get('user_id', 'anonymous')
            session = self.user_sessions[user_id]
            
            # Check various conditions
            if not activity.get('success', True):
                threat = {
                    'threat_id': f"TH-{datetime.now().strftime('%Y%m%d')}-{len(threats)+1:03d}",
                    'timestamp': activity['timestamp'],
                    'user_id': user_id,
                    'activity_type': activity['activity_type'],
                    'algorithm': activity.get('algorithm', 'unknown'),
                    'severity': 'medium',
                    'risk_score': round(session['risk_score'], 2),
                    'anomaly_score': -0.3,
                    'event_type': activity.get('event_type', 'operation_failed'),
                    'explanation': f"Failed {activity.get('activity_type')} operation detected",
                    'recommendation': "Review operation logs and verify key authenticity",
                    'affected_algorithm': activity.get('algorithm', 'unknown')
                }
                threats.append(threat)
        
        return threats
    
    def _analyze_security_events(self) -> List[Dict]:
        """Analyze security events and convert to threats."""
        threats = []
        recent_cutoff = datetime.now() - timedelta(hours=24)
        
        for event in self.security_events:
            event_time = datetime.fromisoformat(event['timestamp'])
            if event_time < recent_cutoff:
                continue
            
            user_id = event['user_id']
            session = self.user_sessions[user_id]
            
            threat = {
                'threat_id': f"TH-{event_time.strftime('%Y%m%d')}-{len(threats)+1:03d}",
                'timestamp': event['timestamp'],
                'user_id': user_id,
                'activity_type': event['details'].get('activity_type', 'unknown'),
                'algorithm': event['details'].get('algorithm', 'unknown'),
                'severity': event.get('severity', 'medium'),
                'risk_score': round(session['risk_score'], 2),
                'anomaly_score': -0.5 if event['severity'] == 'high' else -0.3,
                'event_type': event['event_type'],
                'explanation': self._explain_event(event),
                'recommendation': self._recommend_for_event(event),
                'affected_algorithm': event['details'].get('algorithm', 'unknown')
            }
            threats.append(threat)
        
        return threats
    
    def _explain_event(self, event: Dict) -> str:
        """Generate explainable description for security event."""
        event_type = event['event_type']
        details = event.get('details', {})
        
        explanations = {
            'kyber_decapsulation_failed': "Failed Kyber key decapsulation attempt. Possible key mismatch or ciphertext tampering.",
            'aes_decrypt_failed': "AES decryption operation failed. Possible incorrect key or corrupted ciphertext.",
            'integrity_failure': "Ciphertext integrity check failed. Data may have been modified or tampered with.",
            'iv_reuse': f"Initialization vector reuse detected (IV: {details.get('iv', 'unknown')[:16]}...). IV reuse can compromise encryption security.",
            'key_mismatch': "Key mismatch detected. Operation attempted with incorrect cryptographic key.",
            'operation_failed': "Cryptographic operation failed. Review operation parameters and key validity.",
            'abnormal_frequency': "Abnormally high operation frequency detected. Possible automated attack or system abuse.",
            'data_spike': f"Sudden spike in data volume detected ({details.get('file_size', 0) / (1024*1024):.2f} MB)."
        }
        
        return explanations.get(event_type, f"Security event detected: {event_type}")
    
    def _recommend_for_event(self, event: Dict) -> str:
        """Generate recommendation for security event."""
        event_type = event['event_type']
        
        recommendations = {
            'kyber_decapsulation_failed': "Verify public/private key pair match. Check for ciphertext corruption.",
            'aes_decrypt_failed': "Verify AES key derivation and ciphertext integrity. Check for key rotation issues.",
            'integrity_failure': "Immediate investigation required. Verify data source and transmission integrity.",
            'iv_reuse': "Review IV generation mechanism. Ensure unique IVs for each encryption operation.",
            'key_mismatch': "Verify key management procedures. Check for key rotation or synchronization issues.",
            'operation_failed': "Review operation logs and system configuration. Verify key availability.",
            'abnormal_frequency': "Implement rate limiting. Review user authentication and access controls.",
            'data_spike': "Verify legitimate use case. Consider implementing file size limits."
        }
        
        return recommendations.get(event_type, "Review security logs and system configuration.")
    
    def _calculate_severity(self, anomaly_score: float, activity: Dict, session: Dict) -> str:
        """
        Calculate threat severity level based on multiple factors.
        
        Args:
            anomaly_score: Anomaly score from isolation forest
            activity: Activity dictionary
            session: User session dictionary
            
        Returns:
            Severity level ('low', 'medium', 'high', 'critical')
        """
        risk_score = session['risk_score']
        
        # Critical: Very negative anomaly score + high risk
        if anomaly_score < -0.5 and risk_score > 50:
            return 'critical'
        
        # High: Negative anomaly + medium risk, or integrity/key issues
        if (anomaly_score < -0.3 and risk_score > 30) or \
           activity.get('integrity_check') is False or \
           activity.get('key_mismatch', False):
            return 'high'
        
        # Medium: Moderate anomaly or elevated risk
        if anomaly_score < -0.1 or risk_score > 20:
            return 'medium'
        
        # Low: Minor anomalies
        return 'low'
    
    def _generate_explanation(self, activity: Dict, anomaly_score: float, session: Dict) -> str:
        """
        Generate explainable output describing why a threat was flagged.
        
        Args:
            activity: Activity dictionary
            anomaly_score: Anomaly score
            session: User session dictionary
            
        Returns:
            Human-readable explanation
        """
        explanations = []
        
        # Anomaly score explanation
        if anomaly_score < -0.5:
            explanations.append("Strong anomalous pattern detected in operation behavior")
        elif anomaly_score < -0.3:
            explanations.append("Moderate anomalous pattern detected")
        
        # Risk score explanation
        if session['risk_score'] > 50:
            explanations.append(f"Elevated risk score ({session['risk_score']:.1f}/100) due to recent security events")
        elif session['risk_score'] > 20:
            explanations.append(f"Moderate risk score ({session['risk_score']:.1f}/100)")
        
        # Specific issues
        if not activity.get('success', True):
            explanations.append("Operation failure detected")
        
        if activity.get('integrity_check') is False:
            explanations.append("Data integrity verification failed - possible tampering")
        
        if activity.get('key_mismatch', False):
            explanations.append("Key mismatch event - incorrect cryptographic key used")
        
        if activity.get('file_size', 0) > self.thresholds['large_file_threshold']:
            explanations.append(f"Unusually large file processed ({activity['file_size'] / (1024*1024):.1f} MB)")
        
        # Frequency analysis
        recent_ops = self._count_recent_operations(activity.get('user_id', 'anonymous'), minutes=1)
        if recent_ops > self.thresholds['max_operations_per_minute']:
            explanations.append(f"Abnormal operation frequency ({recent_ops} ops/min)")
        
        return "; ".join(explanations) if explanations else "Anomalous activity pattern detected"
    
    def _generate_recommendation(self, activity: Dict, session: Dict) -> str:
        """Generate security recommendation for detected threat."""
        if activity.get('integrity_check') is False:
            return "Immediate action required: Investigate potential data tampering. Review system logs and verify data source authenticity."
        
        if activity.get('key_mismatch', False):
            return "Verify key management procedures. Check for key rotation or synchronization issues. Review key distribution mechanisms."
        
        if not activity.get('success', True):
            return "Review failed operation logs. Verify key authenticity and operation parameters. Check for system configuration issues."
        
        if session['risk_score'] > 50:
            return "High risk session detected. Consider temporarily restricting access and conducting security audit."
        
        if session['failed_operations'] > 5:
            return "Multiple failed operations detected. Review authentication mechanisms and verify user credentials."
        
        return "Review activity logs and verify user authentication. Monitor for persistent anomalous behavior."
    
    def _generate_synthetic_data(self, count: int = 100) -> List[Dict]:
        """Generate synthetic training data for model initialization."""
        synthetic = []
        base_time = datetime.now()
        
        for i in range(count):
            activity_time = base_time - timedelta(hours=count-i)
            activity = {
                'timestamp': activity_time.isoformat(),
                'activity_type': 'encrypt' if i % 2 == 0 else 'decrypt',
                'file_size': np.random.randint(1024, 10 * 1024 * 1024),
                'success': np.random.random() > 0.1,  # 90% success rate
                'user_id': f'user_{np.random.randint(1, 10)}',
                'algorithm': 'kyber768' if np.random.random() > 0.3 else 'kyber512',
                'hour': activity_time.hour,
                'day_of_week': activity_time.weekday(),
                'integrity_check': np.random.random() > 0.05,  # 95% integrity pass
                'key_mismatch': False
            }
            synthetic.append(activity)
        
        return synthetic
    
    def get_statistics(self) -> Dict:
        """Get statistics about logged activities and threats."""
        if len(self.activity_log) == 0:
            return {
                'total_activities': 0,
                'encryption_count': 0,
                'decryption_count': 0,
                'success_rate': 0,
                'average_file_size': 0,
                'threats_detected': 0,
                'kyber768_usage': 0,
                'kyber512_usage': 0,
                'total_security_events': 0,
                'active_sessions': len(self.user_sessions),
                'high_risk_sessions': sum(1 for s in self.user_sessions.values() if s['risk_score'] > 30)
            }
        
        df = pd.DataFrame(self.activity_log)
        
        stats = {
            'total_activities': len(self.activity_log),
            'encryption_count': len(df[df['activity_type'] == 'encrypt']) if 'activity_type' in df.columns else 0,
            'decryption_count': len(df[df['activity_type'] == 'decrypt']) if 'activity_type' in df.columns else 0,
            'success_rate': df['success'].mean() if 'success' in df.columns else 0,
            'average_file_size': df['file_size'].mean() if 'file_size' in df.columns else 0,
            'threats_detected': len(self.detect_threats()),
            'kyber768_usage': len(df[df['algorithm'] == 'kyber768']) if 'algorithm' in df.columns else 0,
            'kyber512_usage': len(df[df['algorithm'] == 'kyber512']) if 'algorithm' in df.columns else 0,
            'total_security_events': len(self.security_events),
            'active_sessions': len(self.user_sessions),
            'high_risk_sessions': sum(1 for s in self.user_sessions.values() if s['risk_score'] > 30),
            'failed_operations': len(df[df['success'] == False]) if 'success' in df.columns else 0,
            'integrity_failures': len([a for a in self.activity_log if a.get('integrity_check') is False]),
            'key_mismatches': len([a for a in self.activity_log if a.get('key_mismatch', False)])
        }
        
        return stats
    
    def get_session_status(self, user_id: Optional[str] = None) -> Dict:
        """
        Get real-time threat status for user session(s).
        
        Args:
            user_id: Specific user ID, or None for all sessions
            
        Returns:
            Dictionary with session status information
        """
        if user_id:
            session = self.user_sessions.get(user_id, {})
            return {
                'user_id': user_id,
                'risk_score': round(session.get('risk_score', 0), 2),
                'threat_level': self._risk_to_threat_level(session.get('risk_score', 0)),
                'failed_operations': session.get('failed_operations', 0),
                'operation_count': session.get('operation_count', 0),
                'last_activity': session.get('last_activity').isoformat() if session.get('last_activity') else None
            }
        else:
            # Return all sessions
            return {
                'sessions': {
                    uid: {
                        'risk_score': round(s['risk_score'], 2),
                        'threat_level': self._risk_to_threat_level(s['risk_score']),
                        'failed_operations': s['failed_operations'],
                        'operation_count': s['operation_count']
                    }
                    for uid, s in self.user_sessions.items()
                }
            }
    
    def _risk_to_threat_level(self, risk_score: float) -> str:
        """Convert risk score to threat level."""
        if risk_score >= 70:
            return 'critical'
        elif risk_score >= 50:
            return 'high'
        elif risk_score >= 30:
            return 'medium'
        else:
            return 'low'
            
    def block_ip(self, ip_address: str) -> None:
        """Manually add an IP address to the blocklist and set max risk score."""
        self.manual_blocklist.add(ip_address)
        self.user_sessions[ip_address]['risk_score'] = 100.0
    
    def save_log(self, file_path: str) -> None:
        """Save activity log and security events to file."""
        data = {
            'activity_log': list(self.activity_log),
            'security_events': list(self.security_events),
            'user_sessions': {
                k: {
                    'risk_score': v['risk_score'],
                    'failed_operations': v['failed_operations'],
                    'operation_count': v['operation_count'],
                    'last_activity': v['last_activity'].isoformat() if v['last_activity'] else None
                }
                for k, v in self.user_sessions.items()
            }
        }
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def load_log(self, file_path: str) -> None:
        """Load activity log and security events from file."""
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
                self.activity_log = deque(data.get('activity_log', []), maxlen=10000)
                self.security_events = deque(data.get('security_events', []), maxlen=2000)
                # Reconstruct user sessions
                for uid, session_data in data.get('user_sessions', {}).items():
                    self.user_sessions[uid] = {
                        'risk_score': session_data.get('risk_score', 0),
                        'failed_operations': session_data.get('failed_operations', 0),
                        'operation_count': session_data.get('operation_count', 0),
                        'last_activity': datetime.fromisoformat(session_data['last_activity']) if session_data.get('last_activity') else None,
                        'iv_history': set(),
                        'recent_ivs': deque(maxlen=1000)
                    }
            self.train_model()
