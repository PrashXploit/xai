# 🛡️ XAI-Sec: Explainable AI for Cybersecurity

Cybersecurity has become one of the most critical challenges in the digital era due to the exponential growth of cyber-attacks targeting individuals, organizations, and governments. Malware attacks and network intrusions are among the most common threats, often leading to data breaches, financial losses, and system disruptions. With the increasing complexity of attacks, traditional security mechanisms are no longer sufficient to protect modern systems.

Intrusion Detection Systems (IDS) play a vital role in identifying malicious activities within a network. Similarly, malware classification systems help detect and categorize malicious software based on behavior. Earlier systems relied on static analysis and signature matching, which are ineffective against advanced attacks that use obfuscation techniques. As a result, machine learning and deep learning models have been introduced to detect patterns in network traffic and malware behavior dynamically.

Despite their effectiveness, these models suffer from a major limitation: lack of explainability. The predictions made by such models are often not interpretable, making it difficult for security analysts to trust or validate their outputs. This limitation becomes critical in cybersecurity, where incorrect decisions can have serious consequences. Explainable Artificial Intelligence (XAI) has emerged as a solution to this problem by providing insights into how models make decisions.

The XAI-SEC framework is designed to address these challenges by combining intrusion detection and malware classification into a single unified system while integrating explainability techniques. The system not only detects threats but also explains why a particular instance is classified as malicious or benign, thereby improving transparency and reliability.

XAI-Sec is a complete explainable AI cybersecurity platform that integrates intrusion detection, malware analysis, and model interpretability into a unified real-world solution for security operations, monitoring, and decision support.

---

## 🎯 Project Objective

XAI-Sec aims to build a transparent, intelligent, and practical cybersecurity system that:

- detects malicious network traffic using IDS models,
- classifies suspicious files and executables as benign or malicious,
- provides model explanations using SHAP and LIME,
- improves trust, analyst understanding, and decision-making,
- offers a modern interface for monitoring and investigation.

---

## 🚀 Key Features

- **🔍 Intelligent IDS Scanner**: Classifies network traffic patterns (Normal, DoS, Probe, R2L, U2R) with high-confidence ML models.
- **🦠 Advanced Malware Scanner**: Dynamic analysis of multiple file formats (`EXE`, `DLL`, `APK`, `ZIP`, etc.) using entropy and string heuristics.
- **🤖 Explainable AI (XAI)**: Integrated **SHAP** and **LIME** local/global explanations to explain *why* a model made a specific prediction.
- **📊 Professional SOC Dashboard**: High-visibility interface with real-time metrics, global threat distribution, and user activity history.
- **🔐 Secure Authentication**: Multi-user support with encrypted password storage via `bcrypt`.
- **📈 Persistent Analytics**: Comprehensive performance tracking including Accuracy, Precision, Recall, and F1-score with interactive Plotly visualizations.

---

## 🛠️ Tech Stack

- **Frontend**: Streamlit (Modern SOC-style dark theme)
- **Machine Learning**: Scikit-learn (Random Forest, XGBoost), Pandas, NumPy
- **Explainability**: SHAP (Shapley Additive Explanations), LIME (Local Interpretable Model-agnostic Explanations)
- **Visualization**: Plotly, Seaborn, Matplotlib
- **Backend/Security**: SQLite (Persistent storage), Bcrypt (Security)

---

## 📁 Project Structure

```text
XAI-Sec-Project/
├── app/                     # Streamlit web application
│   └── streamlit_app.py     # Main application entry point
├── backend/                 # FastAPI backend for REST APIs
├── database/                # SQLite database and management logic
├── datasets/                # Training and testing datasets (IDS/Malware)
├── explainability/          # XAI implementation (SHAP/LIME)
├── models/                  # Pre-trained PKL models
├── training/                # Model training scripts
├── utils/                   # Data preprocessing and feature extraction
├── frontend/                # Next.js frontend
├── requirements.txt         # Project dependencies
├── start.bat                # Project launcher
├── README.md                # Project documentation
└── PROJECT_STRUCTURE.md     # Architecture overview
```

---

## ⚙️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/PrashXploit/XAI-Sec-Project.git
cd XAI-Sec-Project
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### Run the Application
```bash
streamlit run app/streamlit_app.py
```

### 🛡️ Scanning Workflow
1. **Login/Sign Up**: Access the secure dashboard with your credentials.
2. **IDS Scanner**: Upload a network traffic CSV or generate a sample to detect potential intrusions.
3. **Malware Scanner**: Upload suspicious files for real-time sandbox analysis and classification.
4. **XAI Insights**: Click on the "Model Insights" or "AI Explainability" tabs to view SHAP waterfalls and LIME reasoning.

---

## 🛡️ Responsible AI & security
XAI-Sec is built with **Explainability** at its core. By providing feature-level transparency, security analysts can:
- Validate model reasoning during incident response.
- Identify potential biases in threat detection.
- Meet regulatory compliance for automated decision-making in cybersecurity.

---

## 📄 License
This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---
Developed by **Prashanth** | [GitHub](https://github.com/PrashXploit) | [Contact](mailto:p.prashanth@example.com)
