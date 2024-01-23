# Web Application Firewall Challenge

## Quickstart

```bash
# Backend
flask --app attackdetector run

# Frontend
streamlit run waf_ui.py
```

## Team Specifications:

All teams are required to create a Secure design Specifications Document covering Requirements and threat models.
Application Development Requirements:

## Functional Requirements:

Construct a WAF designed to identify and filter malicious requests, such as:
- XSS
- XSRF
- DOS
- DDOS
- LFI
- SQLInjection
- UnauthorizedRemoteAccess
- UnhandledExceptions
- Buffer overflow
- Determine their origin (IP, Geolocation) for subsequent IP blocking.
- Developfunctionalitycapableofprocessingvarious data types, including strings, JSON, XML, JPG, and others while limiting the size and avoiding malicious Files.
- Implementawhitelistfeatureforverifieduser interfaces (IPs of UIs for example or session management).

## Technologies and tools


1.	User interface
-	Libraries used: Python (Streamlit framework)

2.	BackendAPI
-   Libraries used= flask, requests, flask-limiter
