# Omni Guard

Omni Guard is a dual-module security web application designed to assess the security posture of both software dependencies and server infrastructure. Built with Django, it provides an intuitive interface for scanning project files for known vulnerabilities and evaluating domains or IP addresses for exposed high-risk ports.

##  Features

### 1. Dependency Analysis Module
This module scans project dependency files for known security vulnerabilities using the OSV (Open Source Vulnerabilities) API.
* **Supported Ecosystems:** Node.js and Python (PyPI).
* **Supported Files:** `package.json`, `requirements.txt`, and `Pipfile`.
* **Vulnerability Scoring:** Parses dependencies and their specific versions, cross-references them with the OSV API, and calculates a severity score (0-10) based on the Common Vulnerability Scoring System (CVSS) for each identified vulnerability.

### 2. Infrastructure Module
This module evaluates the external security posture of a target domain or IP address by attempting connections to a predefined list of 21 high-risk ports using Python's `socket.connect_ex()`. 

**Port Evaluation Logic:**
The application categorizes the risk of each port based on the system's socket connection response:
* **Success (`0`):** Port is open. **Risk: True.** (Exploit vector is evaluated based on the specific port's associated risk).
* **Connection Refused (`errno.ECONNREFUSED`):** Port is closed. **Risk: False.** (No direct risk).
* **Timed Out / Blocked (`errno.ETIMEDOUT`, `errno.EAGAIN`, `errno.EWOULDBLOCK`):** Failed to communicate, likely due to a firewall. **Risk: False.** (Port was not reached, which is a positive security outcome).
* **Unevaluated:** Scans returning Host Unreachable (`errno.EHOSTUNREACH`), Network Unreachable (`errno.ENETUNREACH`), or Permission Denied (`errno.EACCES`, `errno.EPERM`) are marked as "Unevaluated" as a definitive status cannot be established.

### 3. Scan History
Omni Guard maintains a persistent history of all dependency and infrastructure scans, allowing users to track security postures over time.

##  Security Posture Grading

The infrastructure module assigns an overall security grade based on the number of exposed high-risk ports. This is calculated using an exponential decay function:

$$S(k) = 100 \cdot e^{-\lambda k}$$

* **$S(k)$**: The final Security Score (0-100).
* **$k$**: The total number of open, high-risk ports detected.
* **$\lambda$ (Decay Constant)**: Set to **0.14**. 

The formula is designed so that a server with zero exposed high-risk ports starts with a perfect score of 100. The decay constant ($\lambda = 0.14$) represents a moderate penalty rate. It isn't overly punitive for a single open port, but as the number of exposed high-risk ports ($k$) increases, the score drops exponentially. This reflects the reality of attack surfaces: each additional exposed port compounds the overall risk to the system.

**Grade Assignment:**
* **A:** Score >= 90
* **B:** Score >= 80
* **C:** Score >= 70
* **D:** Score >= 60
* **F:** Score < 60

##  Tech Stack

* **Backend:** Django, Python
* **Frontend:** Django Templates, HTML/CSS/JS
* **Database:** SQLite3
