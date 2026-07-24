# 🛡️ AI-Driven Cyber Threat Detection System

A Machine Learning-based **Network Intrusion Detection System (NIDS)** that analyzes network traffic data to detect and classify malicious activities in real time. The project leverages the **NSL-KDD benchmark dataset**, advanced data preprocessing techniques, and Machine Learning models to identify potential cyber threats. An interactive **Streamlit** web application enables users to upload network traffic data, generate predictions, and visualize results through an intuitive dashboard.

---

## Overview

Cyber attacks continue to evolve, making traditional signature-based detection methods insufficient for identifying unknown threats. This project presents an AI-driven approach for detecting network intrusions by applying Machine Learning to network traffic data.

The system preprocesses the NSL-KDD dataset, performs feature engineering and class balancing using SMOTE, trains multiple Machine Learning models, and selects the best-performing classifier for deployment. The final solution is integrated into a Streamlit application for real-time threat prediction.

---

## Key Features

- Network Intrusion Detection using Machine Learning
- Data preprocessing and feature engineering
- Label encoding and feature selection
- Class imbalance handling using **SMOTE**
- Comparison of multiple Machine Learning models
- Random Forest selected as the best-performing classifier
- Interactive Streamlit web application
- Real-time threat prediction
- User-friendly dashboard for visualization
- End-to-end Machine Learning pipeline

---

## Technology Stack

| Category | Technologies |
|----------|--------------|
| Programming Language | Python |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn |
| Handling Imbalanced Data | SMOTE (imbalanced-learn) |
| Web Framework | Streamlit |
| Dataset | NSL-KDD Benchmark Dataset |
| Development Environment | Jupyter Notebook |

---

## 📁 Project Structure

```text
AI-Driven-Cyber-Threat-Detection-System/
│
├── .devcontainer/                # Development container configuration
├── KDDTrain+.txt                 # NSL-KDD training dataset
├── KDDTest+.txt                  # NSL-KDD testing dataset
├── app.py                        # Streamlit web application
├── final_file_deployable.ipynb   # Data preprocessing, feature engineering, model training & evaluation
├── model.pkl                     # Trained Random Forest model
├── preprocessor.pkl              # Saved preprocessing pipeline
├── requirements.txt              # Project dependencies
└── README.md                     # Project documentation
```

---

## How It Works

### 1. Dataset Preparation
- Load the NSL-KDD training and testing datasets.
- Clean and preprocess the network traffic data.

### 2. Data Preprocessing
- Handle categorical features using label encoding.
- Perform feature engineering and feature selection.
- Prepare the dataset for Machine Learning.

### 3. Handle Class Imbalance
- Apply **SMOTE** to balance attack and normal classes.
- Improve the model's ability to detect intrusions.

### 4. Model Training
- Train multiple Machine Learning models.
- Compare their performance using evaluation metrics.
- Select **Random Forest** as the final model.

### 5. Deployment

The application is deployed on **Streamlit Community Cloud** and provides an interactive web interface for real-time network intrusion detection.

**🌐 Live Demo:**  
https://ai-driven-cyber-threat-detection-system-7884.streamlit.app/

- Upload network traffic data for analysis.
- Predict whether the traffic is **Normal** or **Malicious**.
- Display prediction results through an interactive dashboard.

---

## 📊 Machine Learning Workflow

```
NSL-KDD Dataset
        │
        ▼
Data Preprocessing
        │
        ▼
Feature Engineering
        │
        ▼
Label Encoding
        │
        ▼
SMOTE
        │
        ▼
Model Training
        │
        ▼
Model Evaluation
        │
        ▼
Best Model (Random Forest)
        │
        ▼
Streamlit Deployment
        │
        ▼
Real-Time Threat Prediction
```

---



---

## 👨‍💻 Author

**Suyash Tripathi**

- GitHub: https://github.com/suyashtripathi656
- LinkedIn: linkedin.com/in/suyash-tripathi-53772827a/

---

## ⭐ If you found this project useful, consider giving it a Star!
