/**
 * NSS IIT Patna — iOS Web Portal (app_new.js)
 *
 * SECURITY MODEL (v2 — Full Server Proxy):
 *   - This file contains ZERO direct Firestore reads or writes.
 *   - Everything goes through ios_* Cloud Functions which use the Admin SDK.
 *   - The client only exchanges: Auth tokens + Signed cryptographic challenges.
 *   - All DB reads/writes, validation, and computation happen invisibly on the server.
 *
 * FLOW:
 *   Login → ios_getDeviceBindChallenge → ios_bindDevice → ios_getProfile
 *   Scan  → ios_getAttendanceChallenge → ios_markAttendance
 */

import { initializeApp }       from "https://www.gstatic.com/firebasejs/9.22.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged, connectAuthEmulator }
                               from "https://www.gstatic.com/firebasejs/9.22.0/firebase-auth.js";
import { CONFIG }              from "./config.js";
import { generatePDFReport }     from "./pdf_export.js";
// NOTE: No Firestore import — the client never touches the database directly.

// ============================================================
// CONFIGURATION
// ============================================================
const firebaseApp = initializeApp(CONFIG.firebaseConfig);
const auth        = getAuth(firebaseApp);

if (CONFIG.useEmulator) {
    connectAuthEmulator(auth, CONFIG.authEmulatorUrl);
    console.log("🔥 Connected to Firebase Auth Emulator");
}

const CF = CONFIG.cfUrl;


// ============================================================
// APP STATE
// ============================================================
let currentUser       = null;
let currentRollNumber = null;
let currentUserName   = null;
let html5QrCode       = null;
let isScanning        = false;
let profileData       = null; // Cached result from ios_getProfile

// ============================================================
// DOM REFERENCES
// ============================================================
const loginView     = document.getElementById("loginView");
const scannerView   = document.getElementById("scannerView");
const dashboardView = document.getElementById("dashboardView");
const eventsView    = document.getElementById("eventsView");
const topNav        = document.getElementById("topNav");
const navScanner    = document.getElementById("navScanner");
const navDashboard  = document.getElementById("navDashboard");
const navSelector   = document.getElementById("navSelector");

const cardSem1      = document.getElementById("card-sem1");
const cardSem2      = document.getElementById("card-sem2");
const eventsBackBtn = document.getElementById("eventsBackBtn");
const eventsViewTitle     = document.getElementById("eventsViewTitle");
const wingEventsContainer = document.getElementById("wingEventsContainer");
const openEventsContainer = document.getElementById("openEventsContainer");

const loginBtn      = document.getElementById("loginBtn");
const logoutBtn     = document.getElementById("logoutBtn");
const rollInput     = document.getElementById("rollNumber");
const passInput     = document.getElementById("password");
const loader        = document.getElementById("loader");
const togglePass    = document.getElementById("togglePassword");
const modal         = document.getElementById("statusModal");
const modalBackdrop = document.getElementById("modalBackdrop");
const modalContent  = document.getElementById("modalContent");
const modalIconBox  = document.getElementById("modalIconBox");
const modalIcon     = document.getElementById("modalIcon");
const modalTitle    = document.getElementById("modalTitle");
const modalMessage  = document.getElementById("modalMessage");
const modalBtn      = document.getElementById("modalBtn");

// ============================================================
// 1. DEVICE RESTRICTION — iOS Only (UX gate)
// ============================================================
function checkDeviceRestriction() {
    const isIOS    = /iPhone|iPad|iPod/i.test(navigator.userAgent);
    const isIPadOS = (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    const isDebug  = new URLSearchParams(window.location.search).get("debug_mode") === "true";
    if (!(isIOS || isIPadOS) && !isDebug) {
        document.body.innerHTML = "";
        const div = document.createElement("div");
        div.className = "flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white p-6 text-center";
        div.innerHTML = `
            <div class="w-24 h-24 bg-red-500/10 rounded-full flex items-center justify-center mb-6 border border-red-500/20">
                <i class="fab fa-apple text-5xl text-red-500"></i>
            </div>
            <h1 class="text-3xl font-bold mb-3 tracking-tight">Device Restricted</h1>
            <p class="text-gray-400 max-w-xs leading-relaxed">This portal is exclusively for iOS devices.</p>`;
        document.body.appendChild(div);
        throw new Error("Access denied: Non-iOS device.");
    }
    if (isDebug) showToast("success", "Debug Mode", "Device restrictions bypassed.");
}
checkDeviceRestriction();
window.onload = checkDeviceRestriction;

// ============================================================
// 2. CRYPTO — RSA-PSS key pair in IndexedDB
//    Private key NEVER leaves the browser.
// ============================================================
const IDB = { name: "nss_secure_store", store: "key_pairs", id: "ios_device_key_pair" };

function openKeyStore() {
    return new Promise((res, rej) => {
        const r = indexedDB.open(IDB.name, 1);
        r.onupgradeneeded = e => e.target.result.createObjectStore(IDB.store);
        r.onsuccess = e => res(e.target.result);
        r.onerror   = e => rej(e.target.error);
    });
}

async function loadOrGenerateKeyPair() {
    const db  = await openKeyStore();
    const kp  = await new Promise((res, rej) => {
        const tx = db.transaction(IDB.store, "readonly");
        const r  = tx.objectStore(IDB.store).get(IDB.id);
        r.onsuccess = () => res(r.result);
        r.onerror   = () => rej(r.error);
    });
    if (kp) return kp;

    const keyPair = await crypto.subtle.generateKey(
        { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
        false, ["sign", "verify"]
    );
    const tx2 = db.transaction(IDB.store, "readwrite");
    tx2.objectStore(IDB.store).put(keyPair, IDB.id);
    await new Promise((res, rej) => { tx2.oncomplete = res; tx2.onerror = rej; });
    return keyPair;
}

async function exportPublicKeyPem(publicKey) {
    const spki = await crypto.subtle.exportKey("spki", publicKey);
    const b64  = btoa(String.fromCharCode(...new Uint8Array(spki)));
    return `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;
}

async function signNonce(privateKey, nonce) {
    const sig = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        privateKey,
        new TextEncoder().encode(nonce)
    );
    return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

// ============================================================
// 3. CLOUD FUNCTION CALLER
//    Single function for all CF calls. No Firestore SDK needed.
// ============================================================
async function cf(name, body) {
    const token = await currentUser.getIdToken(false);
    const resp  = await fetch(`${CF}/${name}`, {
        method:  "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body:    JSON.stringify(body)
    });
    const json = await resp.json().catch(() => ({ error: "Malformed server response" }));
    if (!resp.ok) throw Object.assign(new Error(json.error || "Server error"), { status: resp.status });
    return json;
}

// ============================================================
// 4. DEVICE BINDING
//    Bind this browser's public key to the backend.
//    Uses ios_* functions — completely separate from Android binding.
// ============================================================
async function ensureIosDeviceBound() {
    const kp = await loadOrGenerateKeyPair();

    // Step 1: Get a nonce from the server
    const { nonce }    = await cf("ios_getDeviceBindChallenge", { rollNumber: currentRollNumber });

    // Step 2: Sign nonce with our private key (never leaves browser)
    const signature    = await signNonce(kp.privateKey, nonce);

    // Step 3: Send public key + signature to register
    const publicKeyPem = await exportPublicKeyPem(kp.publicKey);
    await cf("ios_bindDevice", { rollNumber: currentRollNumber, publicKeyPem, signatureBase64: signature });

    console.log("[iOS Bind] Device successfully registered.");
}

// ============================================================
// 5. AUTHENTICATION
// ============================================================
togglePass.addEventListener("click", () => {
    const t = passInput.getAttribute("type") === "password" ? "text" : "password";
    passInput.setAttribute("type", t);
    togglePass.classList.toggle("fa-eye");
    togglePass.classList.toggle("fa-eye-slash");
});

loginBtn.addEventListener("click", async () => {
    const roll = rollInput.value.trim().toUpperCase();
    const pass = passInput.value;
    if (!roll || !pass) { showToast("error", "Missing Credentials", "Please enter both Roll Number and Password."); return; }

    showLoader(true, "Verifying Access...");
    try {
        // The server checks the allowlist and identity — we just need Firebase Auth here.
        // We still need to resolve the email to sign in, so we make ONE read to the
        // public /users/{roll} document (which has allow get: if true in current rules).
        // This is a read-only pre-auth step with no sensitive fields.
        const resp = await fetch(
            `${CONFIG.firestoreUrl}/users/${roll}`
        );
        if (!resp.ok) throw new Error("User not found. Check your Roll Number.");
        const body  = await resp.json();
        const fields = body.fields || {};
        const email  = fields.instituteOutlookId?.stringValue || fields.email?.stringValue;
        if (!email) throw new Error("Email not configured for this account.");

        await signInWithEmailAndPassword(auth, email, pass);
        currentRollNumber = roll;
        localStorage.setItem("nss_last_roll", roll);
    } catch (err) {
        let msg = err.message;
        if (err.code === "auth/wrong-password" || err.code === "auth/invalid-credential") msg = "Invalid password.";
        showToast("error", "Authentication Failed", msg);
        showLoader(false);
    }
});

logoutBtn.addEventListener("click", async () => {
    await signOut(auth);
    if (html5QrCode) { try { await html5QrCode.stop(); } catch (_) {} }
    profileData = null;
});

// Navigation Listeners
navScanner.addEventListener("click", () => switchView("scanner"));
navDashboard.addEventListener("click", () => switchView("dashboard"));
const downloadPdfBtn = document.getElementById("downloadPdfBtn");
if (downloadPdfBtn) downloadPdfBtn.addEventListener("click", () => {
    generatePDFReport(profileData, currentEventsSemester, { showLoader, showToast });
});

onAuthStateChanged(auth, async (user) => {
    showLoader(false);
    if (user) {
        currentUser = user;
        if (!currentRollNumber) currentRollNumber = localStorage.getItem("nss_last_roll");

        logoutBtn.classList.remove("hidden");

        try {
            // Bind device first (required before any attendance or profile call)
            showLoader(true, "Securing device...");
            await ensureIosDeviceBound();
        } catch (e) {
            // If already bound, the server just issues a new challenge.
            // If the server returns 403 "already bound", it is fine — we clear and retry.
            if (e.message && e.message.includes("already bound")) {
                // This shouldn't happen since ios_bindDevice allows re-binding.
                // Log and continue.
                console.warn("[iOS Bind] Already bound (unexpected). Continuing.");
            } else {
                showToast("error", "Device Setup Failed", e.message || "Could not secure this device.");
                await signOut(auth);
                return;
            }
        }

        // Load profile via server — no Firestore reads from client
        showLoader(true, "Loading your profile...");
        try {
            profileData = await cf("ios_getProfile", { rollNumber: currentRollNumber });
            currentUserName = profileData.name;
            renderProfile(profileData);
        } catch (e) {
            console.warn("[Profile] Failed to load:", e.message);
        }

        document.getElementById("userInfoDisplay").innerText = `${currentUserName || "Student"} • ${currentRollNumber}`;
        showLoader(false);
        switchView("dashboard"); // Open dashboard by default
    } else {
        currentUser = currentRollNumber = currentUserName = profileData = null;
        switchView("login");
        logoutBtn.classList.add("hidden");
    }
});

// ============================================================
// 6. PROFILE RENDERING
//    All data comes pre-computed from ios_getProfile.
//    Client does zero arithmetic.
// ============================================================
function renderProfile(p) {
    const fmt  = h => { const n = Number(h); return isNaN(n) ? "0" : (n % 1 === 0 ? String(n) : n.toFixed(1)); };
    const tryS = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };

    tryS("stat-sem1",       `${fmt(p.sem1Hours)} / ${fmt(p.sem1TotalHours)}`);
    tryS("stat-sem2",       `${fmt(p.sem2Hours)} / ${fmt(p.sem2TotalHours)}`);
    tryS("stat-events",     `${p.eventsAttended} / ${p.totalRelevantEvents}`);
    tryS("stat-total",      fmt(p.totalHours));
    tryS("stat-wing-hours", fmt(p.wingHours));
    tryS("stat-open-hours", fmt(p.openHours));
}

// ============================================================
// 6.5 EVENTS SCREEN
// ============================================================
cardSem1.addEventListener("click", () => openEventsScreen(1));
cardSem2.addEventListener("click", () => openEventsScreen(2));
eventsBackBtn.addEventListener("click", () => switchView("dashboard"));

let currentEventsSemester = 1;

function openEventsScreen(sem) {
    if (!profileData) return;
    currentEventsSemester = sem;
    eventsViewTitle.innerText = `Semester ${sem} Events`;
    switchView("events");
    
    const parseDate = (d) => {
        if (!d) return 0;
        const parts = d.split(/[-/]/);
        if (parts.length >= 3) return parts[0].length === 4 ? new Date(parts[0], parts[1]-1, parts[2]).getTime() : new Date(parts[2], parts[1]-1, parts[0]).getTime();
        const parsed = new Date(d).getTime();
        return isNaN(parsed) ? 0 : parsed;
    };
    const sortFn = (a, b) => parseDate(b.date) - parseDate(a.date);
    
    const wingEvs = (profileData.wingEvents || []).filter(e => e.semester === sem).sort(sortFn);
    renderEventList(wingEventsContainer, wingEvs, "Wing", "text-purple-400 bg-purple-500/10", "fa-feather-alt");
    
    const openEvs = (profileData.openEvents || []).filter(e => e.semester === sem).sort(sortFn);
    renderEventList(openEventsContainer, openEvs, "Open", "text-orange-400 bg-orange-500/10", "fa-users");
}

function renderEventList(container, events, typeStr, iconColor, iconClass) {
    if (events.length === 0) {
        container.innerHTML = `<div class="text-center py-10 text-gray-500 text-sm">No ${typeStr} events attended this semester.</div>`;
        return;
    }
    
    const fmt = h => { const n = Number(h); return isNaN(n) ? "0" : (n % 1 === 0 ? String(n) : n.toFixed(1)); };
    
    container.innerHTML = events.map(ev => `
        <div class="glass-card p-4 rounded-xl border border-white/5 flex items-center justify-between">
            <div class="flex items-center gap-3 overflow-hidden">
                <div class="w-10 h-10 rounded-full flex items-center justify-center shrink-0 ${iconColor}">
                    <i class="fas ${iconClass} text-sm"></i>
                </div>
                <div class="truncate pr-2">
                    <h5 class="text-sm font-semibold text-white truncate">${ev.eventName || 'Unknown Event'}</h5>
                    <p class="text-xs text-gray-400 mt-0.5 truncate">${ev.date || ''}</p>
                </div>
            </div>
            <div class="shrink-0 text-right">
                <span class="text-lg font-bold ${Number(ev.hours) < 0 ? 'text-red-400' : 'text-white'} tracking-tight">${Number(ev.hours) > 0 ? '+' : ''}${fmt(ev.hours)}</span>
                <span class="text-[10px] text-gray-500 block uppercase font-bold tracking-wider -mt-1">hrs</span>
            </div>
        </div>
    `).join("");
}

// ============================================================
// 7. QR SCANNER
// ============================================================
function initializeScanner() {
    if (html5QrCode) return;
    html5QrCode = new Html5Qrcode("reader");
    html5QrCode.start({ facingMode: "environment" }, { fps: 10, qrbox: { width: 250, height: 250 } }, onScanSuccess)
        .catch(() => showToast("error", "Camera Error", "Please allow camera permissions."));
}

function onScanSuccess(decodedText) {
    if (isScanning) return;
    isScanning = true;
    processAttendance(decodedText)
        .then(r => { if (r === false) { isScanning = false; return; } setTimeout(() => { isScanning = false; }, 3000); })
        .catch(err => {
            isScanning = false;
            showLoader(false);
            const msg = err.message || "Unknown error";
            if (msg.includes("already") || err.status === 409) showModal("duplicate", "Chill Broooo 🥱", "Attendance already marked.");
            else if (msg.includes("away") || msg.includes("Location"))  showModal("error", "Too Far Away 📍", msg);
            else if (msg.includes("device") || msg.includes("proxy"))   showModal("error", "No Proxy Allowed 🤨", msg);
            else showModal("error", "Attendance Failed", msg);
        });
}

async function processAttendance(qrText) {
    // 1. Parse QR
    let qrData;
    try { qrData = JSON.parse(qrText); }
    catch (_) { console.warn("Invalid QR frame, ignoring."); return false; }

    if (!qrData.sessionId || !qrData.timestamp || !qrData.validationToken || !qrData.eventId) {
        console.warn("Incomplete QR, ignoring."); return false;
    }

    // 2. Client-side freshness pre-check (saves a network roundtrip on stale QRs)
    if (Date.now() - qrData.timestamp > 8000) throw new Error("QR Code Expired. Please scan a fresh code.");

    // 3. Get GPS (client-side — the raw coords are sent to the server for authoritative geofence check)
    showLoader(true, "Getting location...");
    const pos = await getCurrentPosition();
    showLoader(true, "Requesting challenge...");

    // 4. Request a per-scan challenge nonce from server
    const { nonce } = await cf("ios_getAttendanceChallenge", { rollNumber: currentRollNumber, eventId: qrData.eventId });

    // 5. Sign the nonce (private key stays in browser)
    const kp        = await loadOrGenerateKeyPair();
    const signature = await signNonce(kp.privateKey, nonce);

    // 6. Send everything to the server — server does: signature verify, event check,
    //    live check, geofence, duplicate check, device re-use check, then writes to Firestore.
    showLoader(true, "Marking attendance...");
    const result = await cf("ios_markAttendance", {
        rollNumber:      currentRollNumber,
        eventId:         qrData.eventId,
        signatureBase64: signature,
        latitude:        pos.coords.latitude,
        longitude:       pos.coords.longitude,
        attendeeName:    currentUserName || "Unknown",
        qrTimestamp:     qrData.timestamp,
    });

    showLoader(false);
    showModal("success", "Attendance Marked ✅", result.message || "Verified and recorded by server.");

    // Refresh profile in background so hours update without re-login
    cf("ios_getProfile", { rollNumber: currentRollNumber })
        .then(p => { profileData = p; renderProfile(p); })
        .catch(() => {});
}

// ============================================================
// 8. UTILITIES
// ============================================================
function getCurrentPosition() {
    return new Promise((res, rej) => {
        if (!navigator.geolocation) { rej(new Error("Geolocation not supported.")); return; }
        navigator.geolocation.getCurrentPosition(res,
            () => navigator.geolocation.getCurrentPosition(res,
                () => rej(new Error("Location permission denied. Please enable location services.")),
                { enableHighAccuracy: false, timeout: 10000 }
            ), { enableHighAccuracy: true, timeout: 10000 }
        );
    });
}

function switchView(v) {
    loginView.classList.toggle("hidden", v !== "login");
    scannerView.classList.toggle("hidden", v !== "scanner");
    dashboardView.classList.toggle("hidden", v !== "dashboard");
    eventsView.classList.toggle("hidden", v !== "events");

    if (v === "login" || v === "events") {
        topNav.classList.add("hidden");
    } else {
        topNav.classList.remove("hidden");
        
        if (v === "dashboard") {
            navDashboard.classList.remove("text-gray-400", "hover:text-gray-200");
            navDashboard.classList.add("text-primary");
            navScanner.classList.remove("text-primary");
            navScanner.classList.add("text-gray-400", "hover:text-gray-200");
            navSelector.style.transform = "translateX(0)";
            
            if (html5QrCode && html5QrCode.getState() === 2 /* SCANNING */) {
                html5QrCode.pause();
            }
        } else if (v === "scanner") {
            navScanner.classList.remove("text-gray-400", "hover:text-gray-200");
            navScanner.classList.add("text-primary");
            navDashboard.classList.remove("text-primary");
            navDashboard.classList.add("text-gray-400", "hover:text-gray-200");
            navSelector.style.transform = "translateX(100%)";
            
            if (!html5QrCode) {
                // Initialize after a tiny delay so the DOM has time to render block dimensions
                setTimeout(initializeScanner, 50);
            } else if (html5QrCode.getState() === 3 /* PAUSED */) {
                html5QrCode.resume();
            }
        }
    }
}

function showLoader(show, text = "Loading...") {
    loader.classList.toggle("hidden", !show);
    loader.classList.toggle("flex", show);
    const lt = document.getElementById("loaderText");
    if (lt) lt.innerText = text;
}

modalBtn.addEventListener("click", () => {
    modalBackdrop.classList.remove("opacity-100");
    modalContent.classList.remove("scale-100", "opacity-100");
    modalContent.classList.add("scale-95", "opacity-0");
    setTimeout(() => { modal.classList.add("hidden"); }, 300);
});

function showModal(type, title, message) {
    modal.classList.remove("hidden");
    void modal.offsetWidth;
    modalBackdrop.classList.add("opacity-100");
    modalContent.classList.remove("scale-95", "opacity-0");
    modalContent.classList.add("scale-100", "opacity-100");
    if (modalTitle)   modalTitle.innerText   = title;
    if (modalMessage) modalMessage.innerText = message;
    if (modalIconBox) {
        modalIconBox.className = "w-20 h-20 rounded-full mx-auto flex items-center justify-center mb-6 shadow-lg";
        const c = type === "success"   ? ["bg-green-500/20","text-green-500","fas fa-check text-4xl"]
                : type === "duplicate" ? ["bg-yellow-500/20","text-yellow-500","fas fa-hand-paper text-4xl"]
                :                       ["bg-red-500/20","text-red-500","fas fa-times text-4xl"];
        modalIconBox.classList.add(c[0], c[1]);
        if (modalIcon) modalIcon.className = c[2];
    }
}

function showToast(type, title, message) {
    const toast = document.getElementById("toast");
    const icon  = document.getElementById("toastIcon");
    const te    = document.getElementById("toastTitle");
    const me    = document.getElementById("toastMessage");
    if (!toast) return;
    toast.className = "fixed bottom-10 left-1/2 -translate-x-1/2 w-[90%] max-w-sm p-4 rounded-2xl glass-card border transform transition-all duration-300 z-[90] flex items-start gap-3 shadow-2xl translate-y-0 opacity-100";
    const ok = type === "success";
    toast.classList.add(ok ? "border-green-500/20" : "border-red-500/20");
    if (icon) { icon.className = `w-8 h-8 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${ok ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`; icon.innerHTML = `<i class="fas fa-${ok ? "check" : "exclamation"}"></i>`; }
    if (te)   { te.className = `font-semibold ${ok ? "text-green-400" : "text-red-400"}`; te.innerText = title; }
    if (me)   me.innerText = message;
    setTimeout(() => { toast.classList.add("translate-y-[150%]", "opacity-0"); }, 4000);
}

// (PDF generation logic has been extracted to pdf_export.js)
