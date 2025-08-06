# Endcover – Burp Suite Extension for API Endpoint Discovery & Authorization Analysis

**Endcover** is a Burp Suite extension (written in Jython) that assists penetration testers and security researchers in **discovering API endpoints** and **analyzing authentication/authorization controls** with minimal manual effort.  
This extension has proven especially valuable when conducting penetration tests in line with **OWASP WSTG** criteria, streamlining the process of uncovering endpoints and validating access controls.

---

## ✨ Features

### 🔍 API Endpoint Discovery
- **Passive Crawling**: Uses Burp Suite’s Site Map to identify in-scope API endpoints, taking full advantage of **Burp Professional’s Crawler** to expand and populate the Site Map automatically.
- **Proxy History Analysis**: Examines Burp’s proxy history to uncover additional API endpoints, including those that require **conditional requests** or sequence-specific calls before becoming accessible.

### 🔐 Authentication & Authorization Analysis
- Supports **two sets of credentials**:
  - High-privilege (e.g., admin)
  - Low-privilege (e.g., standard user)
- For each discovered endpoint, sends **three request variants**:
  1. **Unauthenticated**
  2. **Low-privilege**
  3. **High-privilege**
- Determines:
  - **Authentication Required** – whether the endpoint rejects unauthenticated requests.
  - **Authorization Enforced** – whether access control differs between privilege levels.

### 📄 Output
- Results displayed in a sortable **Burp tab table** with color-coded auth results.
- Exportable to **CSV** with:
  - Endpoint
  - HTTP Method
  - Parameters
  - Authentication Required (Yes/No)
  - Authorization Enforced (Yes/No)

### ⚙️ Configurable Options
- Enable/disable crawling
- Enable/disable proxy history analysis
- Set authentication type (Cookie or Authorization header)
- Input high-privilege & low-privilege credentials
- Custom API keyword filtering

---

## 📦 Installation
0. Ensure **Jython** is configured in Burp Suite 
```
Extensions → Extensions Settings → Python Environment -> Choose the path where your jython-standalone.jar is located
```
1. Clone this repo from github: 
```
git clone https://github.com/pucagit/Endcover.git
```
1. Load it into Burp Suite via:
```
Extensions → Installed → Add → Extension Type: Python → Select main.py
```

---

## 🚀 Usage
0. Testing around with the target or use Burp's Crawler to discover endpoints
1. Open the **"Endcover"** tab in Burp Suite.
2. Configure:
- Authentication header (e.g., `Authorization` or `Cookie`)
- High-privilege & low-privilege credential values
- API keyword(s) for discovery each separated by a space character
3. Choose whether to:
- Crawl target scope
- Analyze proxy history
4. Click **Start API Discovery**.
5. Review results in the table or export to CSV.

---

## 📊 Example Output
| Endpoint         | HTTP Method | Parameters | Authentication Required | Authorization Enforced |
|------------------|-------------|------------|-------------------------|------------------------|
| /api/admin/users | GET         | -          | Yes                     | Yes                    |
| /api/public/info | GET         | id         | No                      | No                     |

---

## 🛠 Technical Details
- **Multi-threaded** for faster crawling & history analysis.
- **Variant Request Builder** dynamically modifies authentication headers.
- **Response Analyzer** compares HTTP status codes and body differences to detect access control issues (currently in development — planned improvements for more precise and reliable detection).
- **Burp Message Editors** integrated for quick request/response review.

---

## ⚠️ Disclaimer
This tool is intended **for authorized security testing only**. Using it against systems without permission may be illegal.

---