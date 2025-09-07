#!/usr/bin/env python3
"""
Ransomware Detection Model - Enhanced Logistic Regression
Trained on deadbolt_big_dataset.csv for IoT network traffic classification
Integrated with Deadbolt Premium ML detection system
Saves model with joblib for reuse and deployment
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score, roc_auc_score,
    precision_score, recall_score, f1_score, roc_curve, precision_recall_curve
)
from sklearn.linear_model import LogisticRegression
from sklearn.utils import resample
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.pipeline import Pipeline
import joblib
import os
import json
import warnings
from datetime import datetime
warnings.filterwarnings('ignore')

def augment_data_with_realistic_noise(X, y, noise_factor=0.5, augment_ratio=3.0, corruption_rate=0.2):
    """Add realistic noise and corruption to create robust training dataset"""
    print(f"\n🔧 Applying intelligent data augmentation for enhanced robustness...")
    print(f"Original dataset size: {len(X)}")
    
    # Convert to numpy for easier manipulation
    X_array = X.values if hasattr(X, 'values') else X
    
    # Create augmented samples with intelligent noise
    X_augmented = []
    y_augmented = []
    
    # Add original data
    X_augmented.append(X_array)
    y_augmented.append(y)
    
    # Generate intelligent augmented samples
    n_augment = int(len(X) * augment_ratio)
    
    for i in range(n_augment):
        # Select random sample from existing data
        idx = np.random.randint(0, len(X))
        sample = X_array[idx].copy()
        label = y[idx]
        
        # Apply intelligent noise based on feature types
        noise = np.random.normal(0, noise_factor, sample.shape)
        
        # Feature-specific noise patterns
        # Network traffic features (indices 0-4): moderate noise
        for traffic_idx in range(5):
            if traffic_idx < len(sample):
                # Add proportional noise
                sample[traffic_idx] += np.random.normal(0, sample[traffic_idx] * 0.1)
                sample[traffic_idx] = max(0, sample[traffic_idx])  # Keep non-negative
        
        # File changes (index 5): discrete noise
        if len(sample) > 5:
            sample[5] += np.random.choice([-2, -1, 0, 1, 2])  # Small discrete changes
            sample[5] = max(0, sample[5])
        
        # Entropy (index 6): controlled noise to maintain realism
        if len(sample) > 6:
            entropy_noise = np.random.normal(0, 0.3)  # Small entropy variation
            sample[6] += entropy_noise
            sample[6] = np.clip(sample[6], 0, 12)  # Keep in realistic range
        
        # Protocol flags (indices 7-8): occasional flips
        for proto_idx in [7, 8]:
            if proto_idx < len(sample) and np.random.random() < 0.1:
                sample[proto_idx] = 1 - sample[proto_idx]  # Flip protocol
        
        # Apply feature corruption sparingly
        if np.random.random() < corruption_rate:
            corrupt_idx = np.random.randint(0, min(6, len(sample)))  # Don't corrupt protocols
            noise_multiplier = np.random.uniform(0.5, 2.0)
            sample[corrupt_idx] *= noise_multiplier
        
        # Very rare label noise (2% instead of 5%)
        if np.random.random() < 0.02:
            label = 1 - label
        
        X_augmented.append(sample.reshape(1, -1))
        y_augmented.append(np.array([label]))
    
    # Combine all data
    X_final = np.vstack(X_augmented)
    y_final = np.hstack(y_augmented)
    
    # Convert back to DataFrame if input was DataFrame
    if hasattr(X, 'columns'):
        X_final = pd.DataFrame(X_final, columns=X.columns)
    
    print(f"Augmented dataset size: {len(X_final)}")
    print(f"Noise factor: {noise_factor}, Corruption rate: {corruption_rate}")
    print(f"🎯 Intelligent augmentation preserves feature relationships while adding robustness!")
    
    return X_final, y_final

def create_enhanced_features(X):
    """Create additional engineered features for better detection"""
    X_enhanced = X.copy()
    
    # Traffic ratio features
    X_enhanced['bytes_ratio'] = np.where(X['resp_bytes'] > 0, 
                                        X['orig_bytes'] / X['resp_bytes'], 
                                        X['orig_bytes'])
    
    X_enhanced['pkts_ratio'] = np.where(X['resp_pkts'] > 0, 
                                       X['orig_pkts'] / X['resp_pkts'], 
                                       X['orig_pkts'])
    
    # Throughput features
    X_enhanced['orig_throughput'] = np.where(X['duration'] > 0, 
                                            X['orig_bytes'] / X['duration'], 
                                            X['orig_bytes'])
    
    X_enhanced['resp_throughput'] = np.where(X['duration'] > 0, 
                                            X['resp_bytes'] / X['duration'], 
                                            X['resp_bytes'])
    
    # Protocol efficiency
    X_enhanced['protocol_efficiency'] = X['proto_TCP'] * 2 + X['proto_UDP']
    
    # Entropy-based features
    X_enhanced['entropy_category'] = pd.cut(X['entropy'], 
                                           bins=[0, 3, 6, 9, 12], 
                                           labels=[0, 1, 2, 3]).astype(float)
    
    # File change intensity
    X_enhanced['file_change_rate'] = np.where(X['duration'] > 0,
                                             X['file_changes'] / X['duration'],
                                             X['file_changes'])
    
    return X_enhanced

def save_model_metadata(model, scaler, label_encoder, feature_names, performance_metrics, model_dir="models"):
    """Save comprehensive model metadata for integration"""
    metadata = {
        'model_type': 'Enhanced Logistic Regression',
        'training_date': datetime.now().isoformat(),
        'feature_count': len(feature_names),
        'feature_names': feature_names,
        'performance': {
            k: float(v) if isinstance(v, (np.int64, np.int32, np.float64, np.float32)) else v
            for k, v in performance_metrics.items()
        },
        'model_params': {
            k: float(v) if isinstance(v, (np.int64, np.int32, np.float64, np.float32)) else v
            for k, v in model.get_params().items()
        },
        'scaler_type': type(scaler).__name__,
        'label_mapping': {
            str(k): int(v) for k, v in zip(label_encoder.classes_, 
                                         label_encoder.transform(label_encoder.classes_))
        },
        'deadbolt_integration': {
            'compatible': True,
            'version': '2.0',
            'ml_detector_ready': True
        }
    }
    
    metadata_path = os.path.join(model_dir, "model_metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"   Metadata: {metadata_path}")
    return metadata_path

def load_and_preprocess_data(file_path):
    print("Loading dataset...")
    df = pd.read_csv(file_path)
    
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")
    print(f"Label distribution:\n{df['label'].value_counts()}")
    
    # Separate features and target
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Encode labels (malicious=1, benign=0)
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"Features shape: {X.shape}")
    print(f"Target shape: {y_encoded.shape}")
    print(f"Label encoding: {dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))}")
    
    return X, y_encoded, label_encoder

def train_enhanced_logistic_regression_model(X_train, y_train):
    """Train Enhanced Logistic Regression model optimized for Deadbolt integration"""
    print("\nTraining Enhanced Logistic Regression model with advanced techniques...")
    
    # Use RobustScaler for better handling of outliers
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Use GridSearch to find optimal regularization
    print("Performing hyperparameter tuning with cross-validation...")
    
    param_grid = {
        'C': [0.01, 0.1, 1.0, 10.0],    # Wider range for better performance
        'penalty': ['l1', 'l2', 'elasticnet'],  # Include elastic net
        'solver': ['liblinear', 'saga'],         # Multiple solvers
        'l1_ratio': [0.1, 0.5, 0.9]             # For elastic net
    }
    
    # Base model
    base_model = LogisticRegression(
        max_iter=1000,
        random_state=42,
        class_weight='balanced'
    )
    
    # Use StratifiedKFold for better cross-validation
    cv_strategy = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    # Grid search with enhanced cross-validation
    grid_search = GridSearchCV(
        base_model,
        param_grid,
        cv=cv_strategy,
        scoring='roc_auc',
        n_jobs=-1,
        verbose=1,
        return_train_score=True
    )
    
    grid_search.fit(X_train_scaled, y_train)
    
    # Get best model
    best_model = grid_search.best_estimator_
    
    print(f"\nBest parameters found: {grid_search.best_params_}")
    print(f"Best cross-validation AUC: {grid_search.best_score_:.4f}")
    
    # Perform cross-validation on best model
    cv_scores = cross_val_score(best_model, X_train_scaled, y_train, cv=5, scoring='accuracy')
    print(f"Cross-validation accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    
    # Additional validation metrics
    cv_precision = cross_val_score(best_model, X_train_scaled, y_train, cv=cv_strategy, scoring='precision')
    cv_recall = cross_val_score(best_model, X_train_scaled, y_train, cv=cv_strategy, scoring='recall')
    cv_f1 = cross_val_score(best_model, X_train_scaled, y_train, cv=cv_strategy, scoring='f1')
    
    print(f"Cross-validation Precision: {cv_precision.mean():.4f} ± {cv_precision.std():.4f}")
    print(f"Cross-validation Recall: {cv_recall.mean():.4f} ± {cv_recall.std():.4f}")
    print(f"Cross-validation F1-Score: {cv_f1.mean():.4f} ± {cv_f1.std():.4f}")
    
    return best_model, scaler

def evaluate_model(model, scaler, X_test, y_test, label_encoder, feature_names):
    """Evaluate the trained model"""
    print("\nEvaluating Logistic Regression model...")
    
    # Scale test data
    X_test_scaled = scaler.transform(X_test)
    
    # Predictions
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
    
    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    auc_score = roc_auc_score(y_test, y_pred_proba)
    
    print(f"Logistic Regression Model Performance:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"AUC-ROC: {auc_score:.4f}")
    
    print(f"\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    print(f"\nClassification Report:")
    target_names = label_encoder.classes_
    print(classification_report(y_test, y_pred, target_names=target_names))
    
    # Feature coefficients (interpretability advantage of logistic regression)
    coefficients = pd.DataFrame({
        'feature': feature_names,
        'coefficient': model.coef_[0],
        'abs_coefficient': np.abs(model.coef_[0])
    }).sort_values('abs_coefficient', ascending=False)
    
    print(f"\nTop 5 Feature Coefficients (Most Important Features):")
    print(coefficients.head())
    
    print(f"\nModel Intercept: {model.intercept_[0]:.4f}")
    
    return accuracy, auc_score

def save_model(model, scaler, label_encoder, feature_names, model_dir="models"):
    """Save the trained model and all components for reuse"""
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
    
    model_path = os.path.join(model_dir, "ransomware_detection_model.joblib")
    scaler_path = os.path.join(model_dir, "feature_scaler.joblib")
    encoder_path = os.path.join(model_dir, "label_encoder.joblib")
    features_path = os.path.join(model_dir, "feature_names.joblib")
    
    # Save all components
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)
    joblib.dump(feature_names, features_path)
    
    print(f"\n✅ Model saved successfully:")
    print(f"   Model: {model_path}")
    print(f"   Scaler: {scaler_path}")
    print(f"   Label encoder: {encoder_path}")
    print(f"   Feature names: {features_path}")
    
    return model_path

def main():
    """Main execution function with anti-overfitting measures"""
    # Dataset path
    # Get dataset path relative to current file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(current_dir, "dataset", "deadbolt_big_dataset.csv")
    
    try:
        print("🤖 BUILDING ENHANCED LOGISTIC REGRESSION MODEL")
        print("=" * 60)
        print("🔗 Integrating with Deadbolt Premium ML Detection System...")
        print("🛡️ Optimized for real-time ransomware protection...")
        
        # Load and preprocess data
        X, y, label_encoder = load_and_preprocess_data(dataset_path)
        
        # Store feature names for interpretability
        feature_names = X.columns.tolist()
        
        # Apply feature engineering
        print("\n🎯 Step 1: Feature Engineering")
        X_enhanced = create_enhanced_features(X)
        print(f"Enhanced features: {len(X_enhanced.columns)} (original: {len(X.columns)})")
        
        # Apply data augmentation for robustness
        print("\n🎯 Step 2: Intelligent Data Augmentation")
        X_augmented, y_augmented = augment_data_with_realistic_noise(X_enhanced, y, 
                                                                   noise_factor=0.5, 
                                                                   augment_ratio=3.0, 
                                                                   corruption_rate=0.2)
        
        # Multiple train/test splits to validate robustness
        print("\n🎯 Step 3: Robust Cross-Validation")
        accuracies = []
        auc_scores = []
        
        for split_round in range(5):
            print(f"\n--- Split Round {split_round + 1}/5 ---")
            
            # Split data (70% train, 30% test for more challenging evaluation)
            X_train, X_test, y_train, y_test = train_test_split(
                X_augmented, y_augmented, test_size=0.3, random_state=split_round, stratify=y_augmented
            )
            
            print(f"Train set: {len(X_train)}, Test set: {len(X_test)}")
            
            # Train enhanced model
            if split_round == 0:  # Only do expensive grid search once
                model, scaler = train_enhanced_logistic_regression_model(X_train, y_train)
                best_model = model  # Save best model from first round
                best_scaler = scaler
            else:
                # Use same parameters but retrain
                scaler = RobustScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                
                # Get parameters from best model, handling different parameter structures
                params = best_model.get_params()
                model_params = {
                    'C': params.get('C', 1.0),
                    'penalty': params.get('penalty', 'l2'),
                    'solver': params.get('solver', 'liblinear'),
                    'max_iter': 1000,
                    'random_state': 42,
                    'class_weight': 'balanced'
                }
                
                # Add l1_ratio if using elasticnet
                if params.get('penalty') == 'elasticnet':
                    model_params['l1_ratio'] = params.get('l1_ratio', 0.5)
                
                model = LogisticRegression(**model_params)
                model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            accuracy, auc_score = evaluate_model(model, scaler, X_test, y_test, label_encoder, 
                                                list(X_augmented.columns) if hasattr(X_augmented, 'columns') else [f'feature_{i}' for i in range(X_augmented.shape[1])])
            accuracies.append(accuracy)
            auc_scores.append(auc_score)
            
            print(f"Round {split_round + 1} - Accuracy: {accuracy:.4f}, AUC: {auc_score:.4f}")
        
        # Final evaluation
        print("\n🎯 Step 4: Performance Analysis")
        print("=" * 50)
        
        mean_accuracy = np.mean(accuracies)
        std_accuracy = np.std(accuracies)
        mean_auc = np.mean(auc_scores)
        std_auc = np.std(auc_scores)
        
        print(f"Multi-split Accuracy: {mean_accuracy:.4f} ± {std_accuracy:.4f}")
        print(f"Multi-split AUC-ROC: {mean_auc:.4f} ± {std_auc:.4f}")
        
        # Robustness assessment
        if std_accuracy < 0.05 and mean_accuracy > 0.95:
            print("⚠️  WARNING: Still showing signs of overfitting!")
            print("Consider: More noise, larger dataset, or stronger regularization")
        elif mean_accuracy < 0.65:
            print("⚠️  WARNING: Accuracy too low - model underfitting")
            print("Consider: Less regularization or better features")
        else:
            print("✅ Model shows good generalization!")
        
        # Calculate comprehensive performance metrics
        performance_metrics = {
            'mean_accuracy': float(mean_accuracy),
            'std_accuracy': float(std_accuracy),
            'mean_auc': float(mean_auc),
            'std_auc': float(std_auc),
            'cross_validation_scores': [float(x) for x in accuracies],
            'model_stability': 'High' if std_accuracy < 0.05 else 'Medium' if std_accuracy < 0.1 else 'Low'
        }
        
        # Save the enhanced model with metadata
        print("\n🎯 Step 5: Model Persistence & Integration")
        feature_names_enhanced = list(X_enhanced.columns)
        model_path = save_model(best_model, best_scaler, label_encoder, feature_names_enhanced)
        metadata_path = save_model_metadata(best_model, best_scaler, label_encoder, 
                                          feature_names_enhanced, performance_metrics)
        
        print(f"\n{'='*60}")
        print(f"🎉 ENHANCED LOGISTIC REGRESSION MODEL COMPLETED")
        print(f"{'='*60}")
        print(f"🔗 Deadbolt Premium Integration: READY")
        print(f"📊 Performance Summary:")
        print(f"- Mean Accuracy: {mean_accuracy:.4f} ± {std_accuracy:.4f}")
        print(f"- Mean AUC-ROC: {mean_auc:.4f} ± {std_auc:.4f}")
        print(f"- Model Stability: {performance_metrics['model_stability']}")
        print(f"- Features: {len(feature_names_enhanced)} (enhanced)")
        print(f"- Model Type: Enhanced Logistic Regression")
        print(f"- Integration: ML Detector Compatible")
        print(f"\n📁 Files Generated:")
        print(f"- Model: {model_path}")
        print(f"- Metadata: {metadata_path}")
        print(f"\n🚀 Ready for Deadbolt Premium ML Detection System!")
        print(f"\n💡 To integrate: The ml_detector.py will automatically detect and use this model")
        print(f"🛡️ Real-time ransomware protection is now enhanced!")
        
        return mean_accuracy, mean_auc, best_model, best_scaler, label_encoder
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return None, None

if __name__ == "__main__":
    main()