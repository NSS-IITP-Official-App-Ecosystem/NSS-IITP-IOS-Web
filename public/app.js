import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/9.22.0/firebase-auth.js";
import { getFirestore, doc, getDoc, updateDoc, setDoc, arrayUnion, increment, collection, serverTimestamp, GeoPoint, writeBatch } from "https://www.gstatic.com/firebasejs/9.22.0/firebase-firestore.js";

// ==========================================
// 1. CONFIGURATION (USER MUST FILL THIS)
// ==========================================
const firebaseConfig = {
    apiKey: "AIzaSyDWOk35Qtp7Dwrtip0zE8pQDbevLdhk704",
    authDomain: "nssiitp-app.firebaseapp.com",
    projectId: "nssiitp-app",
    storageBucket: "nssiitp-app.firebasestorage.app",
    messagingSenderId: "23318803",
    appId: "1:23318803:web:9bc067213a5f6a7f61cae6",
    measurementId: "G-J805ZLPK12"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// State
let currentUser = null;
let currentRollNumber = null;
let currentUserName = null; // Store fetched name globally
let html5QrCode = null;
let isScanning = false;
// Generate Device ID using Fingerprinting (Persists across Incognito/Clear Cache)
let virtualDeviceId = generateDeviceFingerprint();
console.log("Device Fingerprint:", virtualDeviceId);

// DOM Elements
const loginView = document.getElementById('loginView');
const scannerView = document.getElementById('scannerView');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const rollInput = document.getElementById('rollNumber');
const passInput = document.getElementById('password');
const loader = document.getElementById('loader');
const togglePassword = document.getElementById('togglePassword');
const modal = document.getElementById('statusModal');
const modalBackdrop = document.getElementById('modalBackdrop');
const modalContent = document.getElementById('modalContent');
const modalIconBox = document.getElementById('modalIconBox');
const modalIcon = document.getElementById('modalIcon');
const modalTitle = document.getElementById('modalTitle');
const modalMessage = document.getElementById('modalMessage');
const modalBtn = document.getElementById('modalBtn');

modalBtn.addEventListener('click', () => {
    modalBackdrop.classList.remove('opacity-100');
    modalContent.classList.remove('scale-100', 'opacity-100');
    modalContent.classList.add('scale-95', 'opacity-0');
    setTimeout(() => {
        modal.classList.add('hidden');
        if (html5QrCode && !isScanning) html5QrCode.resume();
    }, 300);
});

function showModal(type, title, message) {
    try {
        if (!modal || !modalBackdrop || !modalContent) {
            console.error("Modal elements not found!");
            alert(`${title}: ${message}`);
            return;
        }

        modal.classList.remove('hidden');
        // Force reflow
        void modal.offsetWidth;

        modalBackdrop.classList.add('opacity-100');
        modalContent.classList.remove('scale-95', 'opacity-0');
        modalContent.classList.add('scale-100', 'opacity-100');

        if (modalTitle) modalTitle.innerText = title;
        if (modalMessage) modalMessage.innerText = message;

        if (modalIconBox) {
            modalIconBox.className = "w-20 h-20 rounded-full mx-auto flex items-center justify-center mb-6 shadow-lg shadow-black/50 transition-colors";

            if (type === 'success') {
                modalIconBox.classList.add('bg-green-500/20', 'text-green-500');
                if (modalIcon) modalIcon.className = "fas fa-check text-4xl";
            } else if (type === 'duplicate') {
                modalIconBox.classList.add('bg-yellow-500/20', 'text-yellow-500');
                if (modalIcon) modalIcon.className = "fas fa-hand-paper text-4xl";
            } else {
                modalIconBox.classList.add('bg-red-500/20', 'text-red-500');
                if (modalIcon) modalIcon.className = "fas fa-times text-4xl";
            }
        }
    } catch (e) {
        console.error("Error showing modal:", e);
        // Fallback to alert if modal fails
        alert(`${title}\n${message}`);
    }
}

// ==========================================
// 2. AUTHENTICATION LOGIC
// ==========================================

// Toggle Password
togglePassword.addEventListener('click', () => {
    const type = passInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passInput.setAttribute('type', type);
    togglePassword.classList.toggle('fa-eye');
    togglePassword.classList.toggle('fa-eye-slash');
});

// Enforce iOS Access (with Debug Bypass)
function checkDeviceRestriction() {
    // 1. Standard User Agent Check
    const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);

    // 2. iPads on iOS 13+ often report as "MacIntel" but have touch points
    const isIPadOS = (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

    const urlParams = new URLSearchParams(window.location.search);
    const isDebug = urlParams.get('debug_mode') === 'true';

    // Allow if: (It is iOS OR It is iPadOS) OR (Debug Mode is ON)
    if (!(isIOS || isIPadOS) && !isDebug) {
        // Clear entire body to prevent flashing of login screen
        document.body.innerHTML = '';

        // Show Restriction Screen
        const restrictionDiv = document.createElement('div');
        restrictionDiv.className = "flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white p-6 text-center animate-fade-in";
        restrictionDiv.innerHTML = `
            <div class="w-24 h-24 bg-red-500/10 rounded-full flex items-center justify-center mb-6 border border-red-500/20 shadow-red-900/20 shadow-lg">
                <i class="fab fa-apple text-5xl text-red-500"></i>
            </div>
            <h1 class="text-3xl font-bold mb-3 tracking-tight">Device Restricted</h1>
            <p class="text-gray-400 max-w-xs leading-relaxed">This portal is exclusively for iOS devices. Please use the Android App for other devices.</p>
        `;
        document.body.appendChild(restrictionDiv);

        // Throw error to stop further script execution
        throw new Error("Access denied: Non-iOS device.");
    }

    if (isDebug) {
        showToast('success', 'Debug Mode', 'Device restrictions bypassed.');
    }
}

// Run protection immediately and on load
checkDeviceRestriction();
window.onload = checkDeviceRestriction;

// Login Handler
loginBtn.addEventListener('click', async () => {
    const roll = rollInput.value.trim().toUpperCase();
    const pass = passInput.value;

    if (!roll || !pass) {
        showToast('error', 'Missing Credentials', 'Please enter both Roll Number and Password.');
        return;
    }

    showLoader(true, 'Verifying Access...');

    try {
        // 1. Check Allowlist
        const allowRef = doc(db, "allowed_ios_users", roll);
        const allowSnap = await getDoc(allowRef);

        if (!allowSnap.exists()) {
            throw new Error("Access Denied. Your Roll Number is not authorized for iOS Web Access.");
        }

        // 2. Fetch User Email from Firestore
        const userRef = doc(db, "users", roll);
        const userSnap = await getDoc(userRef);

        if (!userSnap.exists()) {
            throw new Error("User not found in database.");
        }

        const userData = userSnap.data();
        const email = userData.instituteOutlookId || userData.email;

        if (!email) {
            throw new Error("Email not found for this user.");
        }

        // 3. Authenticate
        await signInWithEmailAndPassword(auth, email, pass);

        // Success (onAuthStateChanged will handle UI switch)
        currentRollNumber = roll;
        localStorage.setItem('nss_last_roll', roll);

    } catch (error) {
        console.error("Login Error:", error);
        let msg = error.message;
        if (error.code === 'auth/wrong-password') msg = "Invalid Password.";
        showToast('error', 'Authentication Failed', msg);
        showLoader(false);
    }
});

// Logout Handler
logoutBtn.addEventListener('click', () => {
    signOut(auth);
    if (html5QrCode) html5QrCode.stop();
});

// Auth State Monitor
onAuthStateChanged(auth, async (user) => {
    showLoader(false);
    if (user) {
        currentUser = user;
        // Try to recover roll number if page refreshed
        if (!currentRollNumber) currentRollNumber = localStorage.getItem('nss_last_roll');

        showToast('success', 'Welcome', 'Ready to mark attendance.');
        switchView('scanner');
        initializeScanner();

        // Update UI
        let displayName = user.displayName;
        if (!displayName || displayName === 'Student') {
            try {
                const userDoc = await getDoc(doc(db, "users", currentRollNumber));
                if (userDoc.exists()) {
                    displayName = userDoc.data().name || userDoc.data().displayName || 'Student';
                }
            } catch (e) {
                console.warn("Failed to fetch user name", e);
            }
        }

        currentUserName = displayName || 'Student'; // Store for later use
        document.getElementById('userInfoDisplay').innerText = `${displayName || 'Student'} • ${currentRollNumber}`;
        logoutBtn.classList.remove('hidden');
    } else {
        currentUser = null;
        currentRollNumber = null;
        switchView('login');
        logoutBtn.classList.add('hidden');
    }
});


// ==========================================
// 3. SCANNER & LOCATION LOGIC
// ==========================================

function initializeScanner() {
    if (html5QrCode) return;

    html5QrCode = new Html5Qrcode("reader");
    const config = { fps: 10, qrbox: { width: 250, height: 250 } };

    html5QrCode.start({ facingMode: "environment" }, config, onScanSuccess)
        .catch(err => {
            console.error("Camera Error", err);
            showToast('error', 'Camera Error', 'Please verify camera permissions.');
        });
}

function onScanSuccess(decodedText, decodedResult) {
    if (isScanning) return;
    isScanning = true;

    // Pause scanning logic handled by isScanning flag
    // html5QrCode.pause(); // Removed to prevent UI freeze

    processAttendance(decodedText)
        .then((result) => {
            // ERROR FIX: If result is false, it means we silently ignored a bad QR/frame.
            // Reset immediately so we can try the next frame suitable.
            if (result === false) {
                isScanning = false;
                return;
            }

            setTimeout(() => {
                isScanning = false;
                // Resume flag only
            }, 3000);
        })
        .catch((err) => {
            console.error("Attendance Process Error:", err);
            isScanning = false;
            // Resume immediately on error so user can retry
            showLoader(false);

            if (err.message && err.message.includes("already marked")) {
                showModal('duplicate', 'Chill Broooo 🥱', 'Attendance already marked.');
            } else if (err.message && (err.message.includes("Location mismatch") || err.message.includes("Device Limit") || err.message.includes("proxy"))) {
                showModal('error', 'No Proxy Allowed 🤨', err.message);
            } else {
                showModal('error', 'Attendance Failed', err.message || "Unknown Error");
            }
        });
}

async function processAttendance(qrText) {
    // 1. Parsing and Validation
    let qrData;
    try {
        qrData = JSON.parse(qrText);
    } catch (e) {
        // ERROR FIX: Silent fail for invalid JSON (e.g. partial scan, background text)
        // Matches Android "silent retry" behavior
        console.warn("Silently ignoring invalid QR format:", e);
        return false;
    }

    // Validate Schema
    if (!qrData.sessionId || !qrData.timestamp || !qrData.validationToken) {
        // ERROR FIX: Silent fail for non-attendance QRs
        console.warn("Silently ignoring incomplete QR data");
        return false;
    }

    // Validate Timestamp (8 seconds window to match Android)
    const now = Date.now();
    if (now - qrData.timestamp > 8000) {
        throw new Error("QR Code Expired. Please scan a fresh code.");
    }

    // 2. Location Check
    showLoader(true, "Checking Location...");
    const position = await getCurrentPosition();
    showLoader(false); // Hide loader but keep processing

    // Fetch Event Location
    const eventRef = doc(db, "NSS_Events_Attendence", qrData.eventId); // Note: Correct spelling based on repo
    const eventSnap = await getDoc(eventRef);

    if (!eventSnap.exists()) throw new Error("Event not found.");

    const eventData = eventSnap.data();
    if (!eventData.isLive && eventData.isLive !== undefined) throw new Error("This event is not live.");

    // ---------------------------------------------------------
    // 2.1 Device Reuse Check (Prevent Multi-Login Proxy)
    // ---------------------------------------------------------
    if (eventData.attendees && Array.isArray(eventData.attendees)) {
        // NOTE: Use camelCase field names
        const alreadyUsed = eventData.attendees.some(att => att.deviceId === virtualDeviceId);

        // Exception: If the SAME user is retrying, we don't block on device ID here. 
        // We let the "Attendance already marked" check (below) handle it for better UX.
        // We only block if device matches BUT user is different.
        const deviceUsedByOther = eventData.attendees.some(att =>
            att.deviceId === virtualDeviceId && att.rollNumber !== currentRollNumber
        );

        if (deviceUsedByOther) {
            throw new Error("This device has already been used by another student.");
        }
    }

    // Use stored location or fallback (simulated logic: assumes Admin set it)
    // NOTE: Use camelCase field names matching Android
    if (eventData.attendanceLocationLatitude && eventData.attendanceLocationLongitude) {
        const dist = getDistanceFromLatLonInKm(
            position.coords.latitude, position.coords.longitude,
            eventData.attendanceLocationLatitude, eventData.attendanceLocationLongitude
        );

        // 100 meters = 0.1 km
        if (dist > 0.1) {
            throw new Error(`Location mismatch. You are ${Math.round(dist * 1000)}m away.`);
        }
    }

    // 3. Mark Attendance
    const attendeeRef = doc(db, `NSS_Events_Attendence/${qrData.eventId}/attendance/${currentRollNumber}`);

    // Check if already marked
    const attendeeSnap = await getDoc(attendeeRef);
    if (attendeeSnap.exists()) {
        throw new Error("Attendance already marked for this event.");
    }

    // Fetch Admin Name
    let adminName = "Admin";
    try {
        const adminSnap = await getDoc(doc(db, "users", qrData.adminId));
        if (adminSnap.exists()) {
            adminName = adminSnap.data().name || adminSnap.data().displayName || "Admin";
        }
    } catch (e) { console.warn("Could not fetch admin name", e); }

    // 3. Use WriteBatch for Atomic Updates
    const batch = writeBatch(db);

    // NOTE: Must match Android 'AttendeeRecord' field names (camelCase)
    const attendeeData = {
        rollNumber: currentRollNumber,
        name: currentUserName || "Unknown",
        scanTimestamp: new Date(),
        scannedFrom: {
            adminRollNumber: qrData.adminId,
            adminName: adminName
        },
        deviceId: virtualDeviceId,
        scanLocation: new GeoPoint(position.coords.latitude, position.coords.longitude),
        manualEntry: false
    };

    // 3.1 Create Attendee Record
    batch.set(attendeeRef, attendeeData);

    // 3.2 Update Event (Atomic)
    batch.update(eventRef, {
        attendees: arrayUnion(attendeeData),
        totalMarked: increment(1)
    });

    // 3.3 Update User Stats
    const hours = eventData.hours || 0;
    const userUpdateRef = doc(db, "users", currentRollNumber);
    batch.update(userUpdateRef, {
        eventsAttended: increment(1),
        hours: increment(hours),
        eventsList: arrayUnion(qrData.eventId)
    });

    // Commit all changes
    await batch.commit();

    showModal('success', 'Attendance Marked', `Attendance Successfully marked for ${eventData.eventName || 'Event'}`);
}


// ==========================================
// 4. UTILITIES
// ==========================================

function switchView(viewName) {
    if (viewName === 'login') {
        loginView.classList.remove('hidden');
        scannerView.classList.add('hidden');
    } else {
        loginView.classList.add('hidden');
        scannerView.classList.remove('hidden');
    }
}

function showLoader(show, text = 'Loading...') {
    loader.classList.toggle('hidden', !show);
    loader.classList.toggle('flex', show);
    document.getElementById('loaderText').innerText = text;
}

function showToast(type, title, message) {
    const toast = document.getElementById('toast');
    const icon = document.getElementById('toastIcon');
    const titleEl = document.getElementById('toastTitle');
    const msgEl = document.getElementById('toastMessage');

    // Reset classes
    toast.className = `fixed top-24 left-1/2 -translate-x-1/2 w-[90%] max-w-sm p-4 rounded-2xl glass-card border transform transition-all duration-300 z-[90] flex items-start gap-3 shadow-2xl translate-y-0 opacity-100`;

    if (type === 'success') {
        toast.classList.add('border-green-500/20');
        icon.className = 'w-8 h-8 rounded-full flex items-center justify-center shrink-0 mt-0.5 bg-green-500/20 text-green-400';
        icon.innerHTML = '<i class="fas fa-check"></i>';
        titleEl.classList.add('text-green-400');
    } else {
        toast.classList.add('border-red-500/20');
        icon.className = 'w-8 h-8 rounded-full flex items-center justify-center shrink-0 mt-0.5 bg-red-500/20 text-red-400';
        icon.innerHTML = '<i class="fas fa-exclamation"></i>';
        titleEl.classList.add('text-red-400');
    }

    titleEl.innerText = title;
    msgEl.innerText = message;

    // Auto hide
    setTimeout(() => {
        toast.classList.remove('translate-y-0', 'opacity-100');
        toast.classList.add('-translate-y-full', 'opacity-0');
    }, 4000);
}

// Promisified Geolocation
// Promisified Geolocation (High Accuracy -> Fallback to Low Accuracy)
function getCurrentPosition() {
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject(new Error("Geolocation is not supported by this browser."));
            return;
        }

        const optionsHigh = { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 };
        const optionsLow = { enableHighAccuracy: false, timeout: 10000, maximumAge: 0 };

        // Try High Accuracy First
        navigator.geolocation.getCurrentPosition(
            resolve,
            (err) => {
                console.warn("High accuracy location failed, trying low accuracy...", err);
                // Fallback to Low Accuracy
                navigator.geolocation.getCurrentPosition(
                    resolve,
                    (errLow) => {
                        console.error("Low accuracy also failed", errLow);
                        reject(new Error("Location permission denied or unavailable. Please ensure 'Location Services' are ON in Windows Settings."));
                    },
                    optionsLow
                );
            },
            optionsHigh
        );
    });
}

function getDistanceFromLatLonInKm(lat1, lon1, lat2, lon2) {
    var R = 6371; // Radius of the earth in km
    var dLat = deg2rad(lat2 - lat1);  // deg2rad below
    var dLon = deg2rad(lon2 - lon1);
    var a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2)
        ;
    var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    var d = R * c; // Distance in km
    return d;
}

function deg2rad(deg) {
    return deg * (Math.PI / 180);
}

// ==========================================
// 5. FINGERPRINTING LOGIC (STICKY UUID)
// ==========================================

function generateDeviceFingerprint() {
    return getStickyDeviceId();
}

/**
 * Gets or creates a persistent "Sticky" Device ID.
 * Uses both localStorage and Cookies for redundancy.
 * If one is cleared, it self-heals from the other.
 */
function getStickyDeviceId() {
    const STORAGE_KEY = 'nss_device_uuid';
    const COOKIE_NAME = 'nss_device_uuid';
    const COOKIE_DAYS = 365;

    // Helper to get cookie
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    // Helper to set cookie
    function setCookie(name, value, days) {
        let expires = "";
        if (days) {
            const date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            expires = "; expires=" + date.toUTCString();
        }
        document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Strict";
    }

    // Helper to generate UUID
    function generateUUID() {
        if (typeof crypto !== 'undefined' && crypto.randomUUID) {
            return crypto.randomUUID();
        }
        // Fallback for older browsers
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    // 1. Try to get from storage
    let localId = localStorage.getItem(STORAGE_KEY);
    let cookieId = getCookie(COOKIE_NAME);
    let finalId = null;

    // 2. Logic to Sync/Heal
    if (localId && cookieId) {
        // Best case: Both exist. Use local.
        if (localId !== cookieId) {
            // Weird mismatch? Trust local (arbitrary choice, but keeps it stable)
            setCookie(COOKIE_NAME, localId, COOKIE_DAYS);
        }
        finalId = localId;
    } else if (localId && !cookieId) {
        // Cookie cleared? Heal it from local.
        setCookie(COOKIE_NAME, localId, COOKIE_DAYS);
        finalId = localId;
    } else if (!localId && cookieId) {
        // LocalStorage cleared? Heal it from cookie.
        localStorage.setItem(STORAGE_KEY, cookieId);
        finalId = cookieId;
    } else {
        // Both missing? New Device.
        finalId = generateUUID();
        localStorage.setItem(STORAGE_KEY, finalId);
        setCookie(COOKIE_NAME, finalId, COOKIE_DAYS);
    }

    return 'web-uuid-' + finalId;
}
}

// Simple string hashing function (DJB2 variant)
function simpleHash(str) {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) + hash) + str.charCodeAt(i); /* hash * 33 + c */
    }
    // Convert to unsigned 32-bit integer hex string
    return (hash >>> 0).toString(16);
}
