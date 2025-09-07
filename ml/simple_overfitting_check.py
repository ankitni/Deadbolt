#!/usr/bin/env python3
"""
Simple Overfitting Check for Ransomware Detection Model
Quick tests to verify if 100% accuracy is legitimate
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

def main():
    print("🔍 OVERFITTING ANALYSIS - Checking 100% Accuracy")
    print("=" * 60)
    
    # Load data
    df = pd.read_csv(r"c:\deadbolt premium\deadboltpremium\ml\dataset\deadbolt_big_dataset.csv")
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"Dataset: {len(X)} samples, {len(X.columns)} features")
    print(f"Classes: Malicious={sum(y_encoded)}, Benign={len(y_encoded)-sum(y_encoded)}")
    
    # TEST 1: Multiple Random Splits
    print(f"\n1️⃣  TEST 1: Multiple Random Splits")
    print("-" * 40)
    
    accuracies = []
    for i in range(10):
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=i, stratify=y_encoded
        )
        
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        model = LogisticRegression(random_state=42)
        model.fit(X_train_scaled, y_train)
        
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        accuracies.append(accuracy)
        
        print(f"Split {i+1:2d}: {accuracy:.4f}")
    
    mean_acc = np.mean(accuracies)
    std_acc = np.std(accuracies)
    
    print(f"\nResult: {mean_acc:.4f} ± {std_acc:.4f}")
    
    if std_acc < 0.01 and mean_acc > 0.99:
        print("⚠️  SUSPICIOUS: Consistently perfect across all splits!")
    else:
        print("✅ Normal variation in accuracy")
    
    # TEST 2: Cross-Validation
    print(f"\n2️⃣  TEST 2: Cross-Validation")
    print("-" * 40)
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = LogisticRegression(random_state=42)
    cv_scores = cross_val_score(model, X_scaled, y_encoded, cv=5, scoring='accuracy')
    
    print(f"CV Scores: {[f'{score:.4f}' for score in cv_scores]}")
    print(f"Mean: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    
    if cv_scores.mean() > 0.99:
        print("⚠️  SUSPICIOUS: Perfect cross-validation scores!")
    else:
        print("✅ Reasonable cross-validation performance")
    
    # TEST 3: Feature Separation Analysis
    print(f"\n3️⃣  TEST 3: Feature Separation Check")
    print("-" * 40)
    
    malicious_mask = y_encoded == 1
    benign_mask = y_encoded == 0
    
    perfect_separators = []
    
    for feature in X.columns:
        mal_min = X[malicious_mask][feature].min()
        mal_max = X[malicious_mask][feature].max()
        ben_min = X[benign_mask][feature].min()
        ben_max = X[benign_mask][feature].max()
        
        # Check for perfect separation (no overlap)
        if mal_max < ben_min or ben_max < mal_min:
            perfect_separators.append(feature)
            print(f"🚨 {feature}: PERFECT SEPARATION")
            print(f"   Malicious: [{mal_min:.2f}, {mal_max:.2f}]")
            print(f"   Benign: [{ben_min:.2f}, {ben_max:.2f}]")
    
    if perfect_separators:
        print(f"\n🚨 CRITICAL: {len(perfect_separators)} features perfectly separate classes!")
        print(f"Perfect separators: {perfect_separators}")
    else:
        print("✅ No perfect feature separation found")
    
    # TEST 4: Simple Rule Test
    print(f"\n4️⃣  TEST 4: Simple Rule Performance")
    print("-" * 40)
    
    # Test if entropy alone can classify perfectly
    entropy_values = X['entropy'].values
    threshold = 5.5  # approximate threshold
    
    simple_predictions = (entropy_values > threshold).astype(int)
    simple_accuracy = accuracy_score(y_encoded, simple_predictions)
    
    print(f"Simple rule: 'entropy > {threshold}' = malicious")
    print(f"Simple rule accuracy: {simple_accuracy:.4f}")
    
    if simple_accuracy > 0.99:
        print("🚨 CRITICAL: Single feature achieves near-perfect accuracy!")
        print("This indicates the dataset is unrealistically easy")
    else:
        print("✅ Single features cannot perfectly classify")
    
    # TEST 5: Regularization Sensitivity
    print(f"\n5️⃣  TEST 5: Regularization Sensitivity")
    print("-" * 40)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    C_values = [0.001, 0.1, 1.0, 100.0]
    
    for C in C_values:
        model = LogisticRegression(C=C, random_state=42, max_iter=1000)
        model.fit(X_train_scaled, y_train)
        
        test_acc = model.score(X_test_scaled, y_test)
        print(f"C = {C:6.3f}: Test accuracy = {test_acc:.4f}")
    
    print("If accuracy stays ~100% regardless of C:")
    print("⚠️  Dataset is linearly separable (too easy)")
    
    # FINAL VERDICT
    print(f"\n" + "="*60)
    print("🎯 OVERFITTING ANALYSIS VERDICT")
    print("="*60)
    
    issues_found = 0
    
    if std_acc < 0.01 and mean_acc > 0.99:
        print("❌ Issue 1: Consistent 100% across random splits")
        issues_found += 1
    
    if cv_scores.mean() > 0.99:
        print("❌ Issue 2: Perfect cross-validation scores")
        issues_found += 1
    
    if len(perfect_separators) > 0:
        print(f"❌ Issue 3: {len(perfect_separators)} features perfectly separate classes")
        issues_found += 1
    
    if simple_accuracy > 0.99:
        print("❌ Issue 4: Single feature achieves near-perfect accuracy")
        issues_found += 1
    
    print(f"\nISSUES FOUND: {issues_found}/4")
    
    if issues_found >= 3:
        print("\n🚨 VERDICT: SEVERE OVERFITTING / UNREALISTIC DATASET")
        print("The model is NOT learning meaningful patterns!")
        print("Recommendations:")
        print("- Get a larger, noisier, real-world dataset")
        print("- Add data augmentation/noise")
        print("- Don't trust this model for production")
    elif issues_found >= 1:
        print("\n⚠️  VERDICT: SUSPICIOUS - POSSIBLE OVERFITTING")
        print("The model may be memorizing rather than learning")
        print("Proceed with caution")
    else:
        print("\n✅ VERDICT: MODEL APPEARS LEGITIMATE")
        print("100% accuracy seems genuine for this dataset")

if __name__ == "__main__":
    main()