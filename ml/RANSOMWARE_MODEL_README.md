# Ransomware Detection Model - Logistic Regression

## Overview
This project contains a **Logistic Regression model** trained to detect ransomware in IoT network traffic using the `deadbolt_big_dataset.csv` dataset. The model is saved with **joblib** for easy reuse and deployment.

## Key Files

### Training & Model
- `logistic_regression_ransomware_detection.py` - Main training script
- `predict_ransomware.py` - Reusable inference script with easy-to-use class

### Saved Model Components (joblib)
- `models/ransomware_detection_model.joblib` - Trained logistic regression model
- `models/feature_scaler.joblib` - StandardScaler for feature preprocessing  
- `models/label_encoder.joblib` - LabelEncoder for target labels
- `models/feature_names.joblib` - Feature names for proper ordering

### Dataset
- `dataset/deadbolt_big_dataset.csv` - Training data (100 samples, 9 features)

## Model Performance
- **Accuracy**: 100% (perfect classification)
- **AUC-ROC**: 1.0000
- **Features**: 9 network traffic features
- **Key Predictor**: `entropy` (coefficient: 0.99)

## Quick Start

### 1. Train the Model
```bash
python logistic_regression_ransomware_detection.py
```

### 2. Use the Model for Predictions
```python
from predict_ransomware import RansomwareDetector

# Initialize detector (loads joblib model automatically)
detector = RansomwareDetector()

# Make a prediction
features = {
    'duration': 4, 'orig_bytes': 9206, 'resp_bytes': 727,
    'orig_pkts': 314, 'resp_pkts': 3, 'file_changes': 334,
    'entropy': 8.27, 'proto_TCP': 1, 'proto_UDP': 1
}

result = detector.predict_single(features)
print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']:.4f}")
```

### 3. Run Interactive Demo
```bash
python predict_ransomware.py
```

## Features Used for Classification

| Feature | Description | Importance |
|---------|-------------|------------|
| `entropy` | Network traffic entropy | **Highest** (0.99) |
| `resp_bytes` | Response bytes count | High (-0.81) |
| `duration` | Connection duration | High (-0.73) |
| `file_changes` | Number of file changes | Medium (0.69) |
| `resp_pkts` | Response packets count | Medium (-0.67) |
| `orig_bytes` | Original bytes count | Low |
| `orig_pkts` | Original packets count | Low |
| `proto_TCP` | TCP protocol flag | Very Low |
| `proto_UDP` | UDP protocol flag | Very Low |

## Model Characteristics

### Why 100% Accuracy?
The dataset shows **perfect feature separation**:
- **Malicious**: entropy range [7.02, 8.98]
- **Benign**: entropy range [2.01, 4.40] 
- **No overlap** between classes

### Decision Rule
A simple rule achieves perfect classification:
```python
if entropy > 5.71:
    return "malicious"
else:
    return "benign"
```

## Usage Examples

### Single Prediction
```python
detector = RansomwareDetector()
result = detector.predict_single([4, 9206, 727, 314, 3, 334, 8.27, 1, 1])
```

### Batch Predictions
```python
import pandas as pd
data = pd.read_csv("new_network_data.csv")
results = detector.predict_batch(data)
```

### Feature Importance
```python
importance = detector.get_feature_importance()
print(importance)
```

## Model Files Structure
```
models/
├── ransomware_detection_model.joblib    # Main model
├── feature_scaler.joblib                # Feature scaling
├── label_encoder.joblib                 # Label encoding  
└── feature_names.joblib                 # Feature ordering
```

## Requirements
- Python 3.x
- pandas >= 1.5.0
- numpy >= 1.21.0  
- scikit-learn >= 1.1.0
- joblib >= 1.1.0

## Installation
```bash
pip install -r requirements.txt
```

## Notes
- Model is trained on a small, clean dataset (100 samples)
- Perfect accuracy indicates synthetic/educational data
- For production use, retrain on larger, noisier real-world datasets
- Model is optimized for interpretability and deployment simplicity