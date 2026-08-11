# 🛡️ Gatekeeper-Proxy

> Dynamic Reverse Proxy, WAF Security Firewall & Sliding-Window Rate Limiter in TypeScript & Node.js.

![Node.js](https://img.shields.io/badge/Node.js-v22+-339933?style=flat&logo=nodedotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7+-3178C6?style=flat&logo=typescript&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

---

## 🌟 Key Features

- ⚡ **Dynamic Reverse Proxying**: Real-time HTTP streaming proxying with load balancing (Round-Robin & Least-Connections) and automated background health checking.
- 🧱 **Built-in Web Application Firewall (WAF)**:
  - IP & CIDR Block Whitelisting / Blacklisting (e.g. `10.0.0.0/24`).
  - Signature-based threat detection against **SQL Injection**, **Cross-Site Scripting (XSS)**, and **Directory / Path Traversal**.
  - Custom regex path rules (e.g. block `/.env`, `/.git`, `/wp-login.php`).
  - Malicious User-Agent filtering (`sqlmap`, `nikto`, `masscan`).
- ⏱️ **Sliding Window Rate Limiter**:
  - Configurable rate limits per IP, per Route, or global limit.
  - Standard HTTP headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`) and `429 Too Many Requests` responses.
- 🔄 **Hot Configuration Reloading**: Auto-detects changes to `gatekeeper.config.json` on disk and updates proxy/firewall rules instantly without dropping connections.
- 📊 **Embedded Visual Admin Dashboard**: Dark-mode web dashboard accessible at `http://localhost:8080/_admin` displaying live request throughput, security threat logs, and quick IP blacklisting tools.
- 🐳 **Docker & Production Ready**: Multi-stage `Dockerfile` and `docker-compose.yml`.

---

## 🏗️ Architecture Overview

```
                        +----------------------------+
                        |  Incoming HTTP Request     |
                        +--------------+-------------+
                                       |
                                       v
                        +----------------------------+
                        |  1. WAF Firewall Engine    | -> [403 Forbidden]
                        |  (IP, CIDR, SQLi, XSS)     | (Logged to Admin)
                        +--------------+-------------+
                                       |
                                       v
                        +----------------------------+
                        |  2. Rate Limiting Engine   | -> [429 Too Many Requests]
                        |  (Sliding Window Log)      | (With Retry-After)
                        +--------------+-------------+
                                       |
                                       v
                        +----------------------------+
                        |  3. Load Balancer & Proxy  |
                        |  (Round-Robin / Streaming) |
                        +--------------+-------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
        +--------------------+                   +--------------------+
        | Backend Target A   |                   | Backend Target B   |
        | (http://127.0.0.1) |                   | (http://127.0.0.1) |
        +--------------------+                   +--------------------+
```

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/tatitoxt/gatekeeper-proxy.git
cd gatekeeper-proxy
npm install
```

### 2. Development Mode (with Hot Reloading)

```bash
npm run dev
```

### 3. Production Build & Run

```bash
npm run build
npm start
```

---

## 🧪 Testing

Run unit and integration tests with Jest:

```bash
npm test
```

---

## ⚙️ Configuration (`gatekeeper.config.json`)

```json
{
  "server": {
    "port": 8000,
    "adminPort": 8080,
    "host": "0.0.0.0"
  },
  "routes": [
    {
      "pathPrefix": "/api/v1",
      "targets": ["http://127.0.0.1:9001", "http://127.0.0.1:9002"],
      "balanceStrategy": "round-robin",
      "rateLimit": {
        "windowMs": 60000,
        "maxRequests": 100
      }
    }
  ],
  "firewall": {
    "enabled": true,
    "ipBlacklist": ["10.0.0.66"],
    "blockedUserAgents": ["sqlmap", "nikto"],
    "wafRules": {
      "blockSqlInjection": true,
      "blockXss": true,
      "blockPathTraversal": true
    }
  },
  "rateLimiter": {
    "globalWindowMs": 60000,
    "globalMaxRequests": 300
  }
}
```

---

## 🛡️ Admin Dashboard & Telemetry API

Access the visual web dashboard in your browser:
👉 **`http://localhost:8080/_admin`**

- **Metrics API**: `GET http://localhost:8080/api/metrics`
- **Routes API**: `GET http://localhost:8080/api/routes`
- **Dynamic Blacklist**: `POST http://localhost:8080/api/firewall/blacklist` `{"ip": "192.168.1.50"}`

---

## 👤 Author

Developed by **Fausto Pastura** ([@tatitoxt](https://github.com/tatitoxt))  
Salesforce Consultant & Forward Deployed AI Engineer.
