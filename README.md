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

## Secure Software Architecture Overview

###	User interface

- Libraries used
  - Python (Streamlit framework)

### Backend API

- Libraries used
  - flask
  - requests
  - flask-limiter

### "Business" Logic Layer

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
- Implement a white list feature for verifieduser interfaces (IPs of UIs for example or session management).

### Monitoring and Logging

- Logging out in plain std out. If deployed onto a server, it will logged to journalctl - will be carried off to corresponding logging servers for further analysis as required
- (TODO) Monitoring to be implemented via exposing `/metrics` endpoint. Metrics will be scraped using standard prometheus tooling