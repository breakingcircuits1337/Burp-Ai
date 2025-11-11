# Atlas AI Pro - Advanced Security Analysis for Burp Suite

[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/your-username/atlas-ai-pro)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional%202025.x-orange.svg)](https://portswigger.net/burp)
[![Python](https://img.shields.io/badge/python-Jython-yellow.svg)](https://www.jython.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Atlas AI Pro is a powerful Burp Suite Professional extension that integrates advanced AI capabilities for offensive security testing. Designed specifically for penetration testers and bug bounty hunters, it provides sophisticated AI-powered analysis with technical, actionable intelligence for real-world exploitation scenarios.

**🔒 Privacy First: Run Your Own Models Locally**

Atlas AI Pro prioritizes your data privacy by supporting completely local AI model deployment. Keep your sensitive security data on your own infrastructure while still leveraging cutting-edge AI analysis capabilities.

## 🚀 Features

### 🤖 Automated & Interactive Reconnaissance
- **Dedicated Recon Tab** - A new top-level tab for running and managing reconnaissance scans.
- **Run Recon Scans** - Execute `nmap` for port scanning and `whatweb` for technology fingerprinting directly from Burp Suite.
- **AI-Powered Summarization** - Get a concise summary of reconnaissance results, including potential attack vectors and recommended next steps.
- **Streamlined Workflow** - Seamlessly integrate reconnaissance into your testing workflow without leaving the Burp Suite environment.

### 🔐 Privacy & Security First
- **Complete Local Deployment** - Run powerful AI models entirely on your own infrastructure
- **Zero Data Transmission** - No sensitive security data leaves your environment
- **Custom Model Support** - Use specialized security-focused models or fine-tuned variants

### Core Analysis Capabilities
- **Advanced Request Analysis** - Deep penetration testing analysis of HTTP requests with focus on authentication bypass, injection vectors, and business logic flaws
- **Response Security Analysis** - Comprehensive response analysis for information disclosure, client-side vulnerabilities, and session management issues
- **Smart Payload Generation** - Advanced payload creation across multiple attack categories (SQLi, XSS, command injection, XXE, SSRF, NoSQL, template injection, deserialization)
- **Selection Explanation** - Context-aware security analysis of any selected text in Burp Suite

### Scanner Integration
- **Dedicated Scanner Findings AI Tab** - Top-level tab for managing all scanner findings with advanced AI analysis
- **Real-time Scanner Listener** - Automatically captures new scanner issues as they're discovered
- **Expert-level Vulnerability Analysis** - Technical analysis, exploitation methodology, impact assessment, and advanced testing scenarios
- **Comprehensive Exploitation Strategies** - Complete roadmaps with reconnaissance, payload development, defensive evasion, and persistence techniques

### AI Backend Support
- **Private Local Models** - Deploy enterprise-grade AI models on your own hardware
- **Multiple Local Platforms** - LM Studio, Ollama, Text Generation WebUI, vLLM, and more
- **OpenAI Integration** - GPT-3.5, GPT-4, and GPT-4-turbo support (optional)
- **Gemini, Mistral, and Groq Integration** - Support for additional powerful cloud-based AI models.
- **Hybrid Deployment** - Mix local and cloud models based on sensitivity

## 📸 Screenshots

### Main Extension Interface
![Main Interface](images/main-interface.png)
*The main Atlas AI Pro interface showing the primary tabs: Atlas AI Config, Atlas AI Analysis, Recon, and Scanner Findings AI*

### Reconnaissance Tab
![Recon Tab](images/recon-tab.png)
*The dedicated Recon tab for running automated scans and getting AI-powered summaries.*

### Scanner Findings AI Tab
![Scanner Findings Tab](images/scanner-findings-tab.png)
*Dedicated Scanner Findings AI tab with real-time issue capture, analysis status tracking, and comprehensive AI analysis results*

### Context Menu Integration
![Context Menu](images/context-menu.png)
*Right-click context menu options available throughout Burp Suite for instant AI analysis*

### AI Analysis Results
![Analysis Results](images/analysis-results.png)
*Example of advanced AI analysis output showing technical details, exploitation steps, and specific payloads*

## 🛠️ Installation

### Prerequisites
- Burp Suite Professional 2025.x
- Python/Jython support in Burp Suite
- `nmap` and `whatweb` installed and available in your system's PATH.
- API access (OpenAI, Gemini, Mistral, Groq API key or local LLM setup)

### Quick Setup

1. **Download the Extension**
   ```bash
   git clone https://github.com/your-username/atlas-ai-pro.git
   cd atlas-ai-pro
   ```

2. **Load in Burp Suite**
   - Go to **Extender → Extensions → Add**
   - Extension Type: **Python**
   - Extension file: **`atlas_ai.py`**
   - Click **Next** and then **Close**

3. **Configure AI Backend**
   - Navigate to the **Atlas AI** tab in Burp Suite
   - Choose your backend:
     - **OpenAI, Gemini, Mistral, or Groq**: Enter your API key from the respective platform.
     - **Local LLM**: Enter your local endpoint URL (e.g., `http://localhost:1234/v1/chat/completions`)
   - Set your preferred model
   - Configure timeout (10-300 seconds)
   - Click **Save Settings**
   - Click **Test Connection** to verify


## 🎯 Usage

### Automated Reconnaissance
1. Go to the **Recon** tab in the main Atlas AI interface.
2. Enter a target domain or IP address in the input field.
3. Click **Start Recon** to begin the scan.
4. The output from `nmap` and `whatweb` will be displayed in real-time.
5. Once the scan is complete, click **Get AI Summary** to receive a concise analysis of the findings.

### Basic Analysis

#### HTTP Request/Response Analysis
1. Right-click any HTTP message in Burp Suite
2. Select **Atlas AI: Analyze Request** or **Atlas AI: Analyze Response**
3. Results appear in the **Atlas AI** tab within that message editor

#### Payload Generation
1. Right-click any HTTP message
2. Select **Atlas AI: Generate Attack Vectors**
3. Receive advanced payloads across multiple attack categories

#### Selection Explanation
1. Highlight any text in Burp Suite
2. Right-click and select **Atlas AI: Explain Selection**
3. Get detailed security analysis of the selected content

### Scanner Integration

#### Automated Scanner Findings
- New scanner issues are automatically captured in the **Scanner Findings AI** tab
- Tab flashes orange when new findings arrive
- View all findings in a filterable table with status tracking

#### Manual Analysis
1. Right-click any scanner issue (in Scanner results or Target Site Map)
2. Choose analysis type:
   - **Atlas AI: Analyze & Explain Finding** - Comprehensive vulnerability analysis
   - **Atlas AI: Suggest Exploitation** - Detailed exploitation strategies
3. Results appear in the **Scanner Findings AI** tab
