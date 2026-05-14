<div align="center">

# NSS-IITP iOS Web — Attendance Portal

**Browser-based QR attendance scanner for iOS users**

[![HTML](https://img.shields.io/badge/Built%20with-HTML%2FJS-E34F26?logo=html5&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/HTML)
[![Tailwind](https://img.shields.io/badge/Styled%20with-Tailwind%20CSS-06B6D4?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Firebase](https://img.shields.io/badge/Backend-Firebase-FFCA28?logo=firebase&logoColor=black)](https://firebase.google.com/)
[![Live Portal](https://img.shields.io/badge/Live%20Portal-nssiitp--app.web.app-FF6B00?logo=firebase&logoColor=white)](https://nssiitp-app.web.app)
[![Main App](https://img.shields.io/badge/Main%20App-NSS--IITP--Official--App-7F52FF?logo=kotlin&logoColor=white)](https://github.com/NSS-IITP-Official-App-Ecosystem/NSS-IITP-Official-App)

</div>

---

## 📖 What is this?

The NSS-IITP Android app includes a hardware-secured QR attendance system — but iOS users can't install the Android app. This web portal bridges that gap.

It gives iOS users a **browser-based QR scanner** that:
- Logs in using their roll number + password (verified against Firestore)
- Activates the device camera to scan the admin's QR code
- Verifies the user is **within 100m** of the venue via GPS
- Submits attendance to the same Firebase backend as the Android app

🔗 **Live:** [nssiitp-app.web.app](https://nssiitp-app.web.app)

> ⚠️ **Restricted access** — this portal is for NSS IITP members only.

---

## ✨ Features

| Feature | Detail |
|---|---|
| **Auth** | Roll number + password login, verified against Firestore |
| **QR Scanning** | Browser-based camera scanner via `html5-qrcode` |
| **Geofence Check** | GPS-based proximity validation (≤100m from venue) |
| **Realtime Feedback** | Toast notifications + result modal on scan |
| **Responsive UI** | Glassmorphism dark theme, works on any mobile browser |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Structure | HTML5 |
| Styling | Tailwind CSS (CDN), custom CSS animations |
| Logic | Vanilla JavaScript (ES Modules) |
| QR Scanning | [html5-qrcode](https://github.com/mebjas/html5-qrcode) |
| Backend | Firebase Firestore + Firebase Auth |
| Typography | Google Fonts — Outfit |
| Icons | Font Awesome 6 |

---

## 🔄 How It Works

```
1. User opens the portal on an iOS browser
2. Enters roll number + password → verified against Firestore
3. Camera activates → scans the admin's event QR code
4. GPS location is captured → checked to be within 100m of venue
5. Attendance record is written to Firebase (same schema as Android app)
6. Success/failure modal is shown
```

---

## 🗂️ Project Structure

```
public/
├── index.html      # App shell — login view + scanner view
├── app.js          # Firebase auth, QR scan logic, attendance submission
├── style.css       # Custom animations (blob, fade, pulse)
└── nss_logo.png    # NSS logo asset
```

---

## 🌐 Ecosystem

This portal is part of the NSS IITP Official App Ecosystem:

| Repo | Description |
|---|---|
| 📱 **[NSS-IITP-Official-App](https://github.com/NSS-IITP-Official-App-Ecosystem/NSS-IITP-Official-App)** | Android app (Kotlin + Compose + Firebase) |
| 🌍 **[NSS-IITP-IOS-Web](https://github.com/NSS-IITP-Official-App-Ecosystem/NSS-IITP-IOS-Web)** ← *you are here* | iOS web attendance portal (HTML/JS) |
| 📸 **[NSS-IITP-App-Showcase](https://github.com/NSS-IITP-Official-App-Ecosystem/NSS-IITP-App-Showcase)** | Visual showcase with 51 screenshots |

---

## 📄 License

MIT License — see the [main app repository](https://github.com/NSS-IITP-Official-App-Ecosystem/NSS-IITP-Official-App) for details.

---

<div align="center">
Part of the <a href="https://github.com/NSS-IITP-Official-App-Ecosystem">NSS IITP Official App Ecosystem</a>
</div>
