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

## 📊 Dataset

This project utilizes the **NSL-KDD** dataset, a widely recognized benchmark for evaluating **Network Intrusion Detection Systems (NIDS)**. The dataset is an improved version of the KDD'99 dataset, designed to eliminate redundant records and provide a more balanced and reliable benchmark for machine learning-based intrusion detection research.

The dataset consists of **41 network traffic features** and a target label indicating whether a network connection is **Normal** or represents an **Attack**. It includes separate training and testing datasets, enabling consistent evaluation of intrusion detection models.

**Dataset Source:**  
https://www.kaggle.com/datasets/hassan06/nslkdd

**Files Used:**
- `KDDTrain+.txt` – Training dataset
- `KDDTest+.txt` – Testing dataset

**Applications:**
- Network Intrusion Detection
- Cybersecurity Research
- Binary & Multi-class Classification
- Machine Learning Model Evaluation

**Acknowledgment:**  
This project uses the publicly available **NSL-KDD** benchmark dataset for educational and research purposes. Credit goes to the original NSL-KDD dataset authors and the Kaggle dataset publisher.

---

## 👨‍💻 Author

**Suyash Tripathi**

- GitHub: https://github.com/suyashtripathi656
- LinkedIn: https://www.linkedin.com/in/suyash-tripathi-53772827a/

---

## ⭐ If you found this project useful, consider giving it a Star!
