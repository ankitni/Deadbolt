#!/usr/bin/env python3
"""
Overfitting Analysis for Ransomware Detection Model
Comprehensive tests to determine if 100% accuracy indicates overfitting
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, validation_curve, learning_curve
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report
import warnings
warnings.filterwarnings('ignore')

def load_data():
    """Load and prepare the dataset"""
    df = pd.read_csv(r"c:\deadbolt premium\deadboltpremium\ml\dataset\deadbolt_big_dataset.csv")
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    return X, y_encoded, label_encoder

def test_different_splits(X, y, n_tests=10):
    """Test model performance with different random splits"""
    print("="*60)
    print("TEST 1: DIFFERENT RANDOM SPLITS")
    print("="*60)
    print("Testing if 100% accuracy persists across different train/test splits...")
    
    accuracies = []
    
    for i in range(n_tests):
        # Different random state each time
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=i, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model
        model = LogisticRegression(random_state=42, class_weight='balanced')
        model.fit(X_train_scaled, y_train)
        
        # Test accuracy
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        accuracies.append(accuracy)
        
        print(f"Split {i+1:2d}: Accuracy = {accuracy:.4f}")
    
    print(f"\nSummary:")
    print(f"Mean accuracy: {np.mean(accuracies):.4f} ± {np.std(accuracies):.4f}")
    print(f"Min accuracy: {np.min(accuracies):.4f}")
    print(f"Max accuracy: {np.max(accuracies):.4f}")
    
    if np.std(accuracies) < 0.01:
        print("⚠️  CONSISTENT 100% - Strong indication of overfitting!")
    else:
        print("✅ Accuracy varies - Normal behavior")
    
    return accuracies

def cross_validation_analysis(X, y):
    """Perform k-fold cross-validation"""
    print("\n" + "="*60)
    print("TEST 2: K-FOLD CROSS-VALIDATION")
    print("="*60)
    print("Testing model stability with cross-validation...")
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Test different k values
    k_values = [3, 5, 10]
    
    for k in k_values:
        if k > len(np.unique(y)):  # Skip if k > number of classes
            continue
            
        print(f"\n{k}-Fold Cross-Validation:")
        
        model = LogisticRegression(random_state=42, class_weight='balanced')
        
        try:
            cv_scores = cross_val_score(model, X_scaled, y, cv=k, scoring='accuracy')
            
            print(f"Scores: {[f'{score:.4f}' for score in cv_scores]}")
            print(f"Mean: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
            
            if cv_scores.std() < 0.01 and cv_scores.mean() > 0.99:
                print("⚠️  All folds near 100% - Likely overfitting!")
            else:
                print("✅ Normal cross-validation behavior")
                
        except Exception as e:
            print(f"Error in {k}-fold CV: {str(e)}")

def learning_curve_analysis(X, y):
    """Analyze learning curves to detect overfitting"""
    print("\n" + "="*60)
    print("TEST 3: LEARNING CURVES")
    print("="*60)
    print("Analyzing if model memorizes vs. learns...")
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = LogisticRegression(random_state=42, class_weight='balanced', max_iter=1000)
    
    # Define training sizes
    train_sizes = np.linspace(0.1, 1.0, 10)
    
    try:
        train_sizes_abs, train_scores, val_scores = learning_curve(
            model, X_scaled, y, train_sizes=train_sizes, cv=3, 
            scoring='accuracy', random_state=42
        )
        
        train_mean = np.mean(train_scores, axis=1)
        train_std = np.std(train_scores, axis=1)
        val_mean = np.mean(val_scores, axis=1)
        val_std = np.std(val_scores, axis=1)
        
        print("\nLearning Curve Results:")
        print("Train Size | Train Acc  | Val Acc    | Gap")
        print("-" * 45)
        
        for i, size in enumerate(train_sizes_abs):
            gap = train_mean[i] - val_mean[i]
            print(f"{size:8.0f}   | {train_mean[i]:.4f}    | {val_mean[i]:.4f}    | {gap:.4f}")
        
        # Check for overfitting signs
        final_gap = train_mean[-1] - val_mean[-1]
        if final_gap > 0.1:
            print(f"\n⚠️  Large gap ({final_gap:.4f}) between train/val - Overfitting!")
        elif val_mean[-1] > 0.99:
            print(f"\n⚠️  Perfect validation accuracy - Dataset too easy!")
        else:
            print(f"\n✅ Normal learning behavior")
            
    except Exception as e:
        print(f"Error in learning curve analysis: {str(e)}")

def regularization_sensitivity(X, y):
    """Test sensitivity to regularization strength"""
    print("\n" + "="*60)
    print("TEST 4: REGULARIZATION SENSITIVITY")
    print("="*60)
    print("Testing if stronger regularization affects performance...")
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Test different C values (inverse regularization strength)
    C_values = [0.001, 0.01, 0.1, 1.0, 10.0, 100.0, 1000.0]
    
    print("\nRegularization Test:")
    print("C Value  | Train Acc | Test Acc  | Gap")
    print("-" * 40)
    
    for C in C_values:
        model = LogisticRegression(C=C, random_state=42, class_weight='balanced', max_iter=1000)
        model.fit(X_train, y_train)
        
        train_acc = model.score(X_train, y_train)
        test_acc = model.score(X_test, y_test)
        gap = train_acc - test_acc
        
        print(f"{C:7.3f}  | {train_acc:.4f}   | {test_acc:.4f}   | {gap:.4f}")
    
    print(f"\nIf test accuracy stays ~100% regardless of C:")
    print(f"⚠️  Dataset is linearly separable - Model not truly learning complexity")

def feature_permutation_test(X, y):
    """Test if shuffling features destroys performance"""
    print("\n" + "="*60)
    print("TEST 5: FEATURE PERMUTATION")
    print("="*60)
    print("Testing if model depends on actual feature values...")
    
    # Original performance
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    model = LogisticRegression(random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    original_acc = model.score(X_test, y_test)
    
    print(f"Original accuracy: {original_acc:.4f}")
    
    # Test each feature
    feature_names = X.columns
    
    print(f"\nFeature Permutation Results:")
    print("Feature       | Accuracy | Drop")
    print("-" * 35)
    
    for i, feature in enumerate(feature_names):
        # Create copy and shuffle one feature
        X_test_perm = X_test.copy()
        X_test_perm[:, i] = np.random.permutation(X_test_perm[:, i])
        
        acc_perm = model.score(X_test_perm, y_test)
        drop = original_acc - acc_perm
        
        print(f"{feature:12} | {acc_perm:.4f}   | {drop:.4f}")
        
        if drop < 0.01:  # Less than 1% drop
            print(f"  ⚠️  Feature {feature} seems unimportant!")

def noise_robustness_test(X, y):
    """Test robustness to noise in features"""
    print("\n" + "="*60)
    print("TEST 6: NOISE ROBUSTNESS")
    print("="*60)
    print("Testing if model is robust to feature noise...")
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model
    model = LogisticRegression(random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    
    # Test with different noise levels
    noise_levels = [0.0, 0.1, 0.2, 0.5, 1.0, 2.0]
    
    print(f"\nNoise Robustness Results:")
    print("Noise Level | Accuracy | Drop")
    print("-" * 30)
    
    for noise_std in noise_levels:
        # Add Gaussian noise
        X_test_noisy = X_test + np.random.normal(0, noise_std, X_test.shape)
        
        try:
            acc_noisy = model.score(X_test_noisy, y_test)
            drop = model.score(X_test, y_test) - acc_noisy
            
            print(f"{noise_std:10.1f} | {acc_noisy:.4f}   | {drop:.4f}")
            
        except Exception as e:
            print(f"{noise_std:10.1f} | Error    | -")

def data_leakage_check(X, y):
    """Check for potential data leakage"""
    print("\n" + "="*60)
    print("TEST 7: DATA LEAKAGE CHECK")
    print("="*60)
    print("Checking for suspicious patterns...")
    
    df_full = X.copy()
    df_full['label'] = y
    
    print(f"\nClass separation analysis:")
    
    # Check feature ranges by class
    malicious_mask = y == 1
    benign_mask = y == 0
    
    perfect_separators = []
    
    for feature in X.columns:
        mal_min, mal_max = X[malicious_mask][feature].min(), X[malicious_mask][feature].max()
        ben_min, ben_max = X[benign_mask][feature].min(), X[benign_mask][feature].max()
        
        # Check for perfect separation
        if mal_max < ben_min or ben_max < mal_min:
            perfect_separators.append(feature)
            print(f"⚠️  {feature}: PERFECT SEPARATION")
            print(f"    Malicious: [{mal_min:.2f}, {mal_max:.2f}]")
            print(f"    Benign: [{ben_min:.2f}, {ben_max:.2f}]")
    
    if perfect_separators:
        print(f"\n🚨 MAJOR CONCERN: {len(perfect_separators)} features have perfect separation!")
        print(f"Features: {perfect_separators}")
        print(f"This explains the 100% accuracy - dataset is unrealistic!")
    else:
        print(f"\n✅ No perfect separation found")

def overfitting_summary():
    """Provide final overfitting assessment"""
    print("\n" + "="*60)
    print("OVERFITTING ANALYSIS SUMMARY")
    print("="*60)
    
    print(f"\n🔍 INDICATORS TO WATCH FOR:")
    print(f"1. Consistent 100% across all splits → Dataset too easy")
    print(f"2. Perfect cross-validation scores → Memorization")
    print(f"3. Large train/validation gap → Classic overfitting")
    print(f"4. Insensitive to regularization → Linear separability")
    print(f"5. Robust to feature permutation → Spurious patterns")
    print(f"6. Perfect feature separation → Data leakage/synthetic data")
    
    print(f"\n💡 RECOMMENDATION:")
    print(f"If multiple tests show 100% accuracy, the model is likely:")
    print(f"- Learning trivial patterns")
    print(f"- Working on synthetic/unrealistic data")
    print(f"- Not suitable for real-world deployment")

def main():
    """Run comprehensive overfitting analysis"""
    print("🔍 COMPREHENSIVE OVERFITTING ANALYSIS")
    print("Testing if 100% accuracy indicates overfitting...")
    
    # Load data
    X, y, label_encoder = load_data()
    
    print(f"\nDataset Info:")
    print(f"- Samples: {len(X)}")
    print(f"- Features: {len(X.columns)}")
    print(f"- Classes: {len(np.unique(y))} (Malicious: {sum(y)}, Benign: {len(y) - sum(y)})")
    
    try:
        # Run all tests
        test_different_splits(X, y)
        cross_validation_analysis(X, y)
        learning_curve_analysis(X, y)
        regularization_sensitivity(X, y)
        feature_permutation_test(X, y)
        noise_robustness_test(X, y)
        data_leakage_check(X, y)
        overfitting_summary()
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
    
    print(f"\n🎯 CONCLUSION:")
    print(f"Review the test results above to determine if 100% accuracy is legitimate")
    print(f"or indicates overfitting/data quality issues.")

if __name__ == "__main__":
    main()