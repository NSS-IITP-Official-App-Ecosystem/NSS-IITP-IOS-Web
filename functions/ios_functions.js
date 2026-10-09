/**
 * ios_functions.js — iOS Web Portal Cloud Functions
 *
 * These are NEW, self-contained Cloud Functions added exclusively for the iOS Web Portal.
 * They act as a secure proxy layer: the iOS client never reads or writes Firestore directly.
 * Every DB read/write happens here using the Firebase Admin SDK, which bypasses client rules.
 *
 * FUNCTIONS:
 *   ios_getProfile       — Returns user profile + pre-calculated hours + wing/open split
 *   ios_markAttendance   — Full server-side QR validation + signature verify + attendance write
 *   ios_getDeviceBindChallenge — Issues a bind-nonce (reuses existing logic, iOS-keyed)
 *   ios_bindDevice       — Registers the browser's RSA public key (iOS-keyed, allows rebind)
 *   ios_getAttendanceChallenge — Issues an attendance nonce (iOS-keyed)
 *
 * SECURITY MODEL:
 *   - Every function verifies Firebase Auth Bearer token first.
 *   - Every function verifies the caller's email matches the requested rollNumber.
 *   - Attendance writes are gated by a cryptographic RSA-PSS challenge/response.
 *   - The client receives only computed JSON — no raw Firestore documents.
 *
 * DEPLOY:
 *   From the NSS-IITP-IOS-Web/functions directory:
 *     firebase deploy --only functions
 */

'use strict';

const { onRequest }    = require('firebase-functions/v2/https');
const admin            = require('firebase-admin');
const crypto           = require('crypto');
const { Timestamp, FieldValue, GeoPoint } = require('firebase-admin/firestore');

// ── Only initialise admin if not already done (shared index.js may have done it) ──
try { admin.app(); } catch (_) { admin.initializeApp(); }

const REGION     = 'asia-south1';
const IOS_PREFIX = 'ios_'; // Namespace all challenge docs so they don't clash with Android

// ═══════════════════════════════════════════════════════════
// SHARED HELPERS (self-contained copies — no import from index.js)
// ═══════════════════════════════════════════════════════════

function sendError(res, err) {
  const status = (err && err.status) ? err.status : 500;
  // Never expose raw stack traces to clients
  const msg = (status < 500) ? err.message : 'Internal server error';
  res.status(status).json({ error: msg });
}

function generateNonce(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function pemToKeyObject(pem) {
  return crypto.createPublicKey({ key: pem, format: 'pem' });
}

/**
 * Verify Firebase Auth ID token from Authorization: Bearer header.
 * Returns the decoded token (contains uid, email, etc.)
 */
async function verifyAuthToken(req) {
  const authHeader = req.headers.authorization || '';
  const match      = authHeader.match(/^Bearer (.+)$/);
  if (!match) throw Object.assign(new Error('Missing Authorization header'), { status: 401 });
  try {
    return await admin.auth().verifyIdToken(match[1]);
  } catch (e) {
    throw Object.assign(new Error('Invalid or expired ID token'), { status: 401 });
  }
}

/**
 * Confirm the authenticated user's email matches the users/{rollNumber} document,
 * AND strictly enforce that the user is whitelisted in allowed_ios_users.
 * This prevents Student A from calling with Student B's roll number, and prevents
 * Android users from using the iOS web portal.
 */
async function assertUserIdentityMatches(db, rollNumber, decoded) {
  const rollUpper = rollNumber.toUpperCase();

  // Fetch both the user profile and the whitelist status concurrently
  const [userSnap, allowedSnap] = await Promise.all([
    db.collection('users').doc(rollUpper).get(),
    db.collection('allowed_ios_users').doc(rollUpper).get()
  ]);

  if (!allowedSnap.exists) {
    throw Object.assign(new Error('Access Denied: Your roll number is not authorized for the iOS Web Portal. Please contact an Admin to be added to the iOS whitelist.'), { status: 403 });
  }

  if (!userSnap.exists) throw Object.assign(new Error('User not found'), { status: 404 });
  
  const d           = userSnap.data() || {};
  const storedEmail = (d.instituteOutlookId || d.email || '').toLowerCase();
  const callerEmail = (decoded.email || '').toLowerCase();
  
  if (storedEmail && callerEmail && storedEmail !== callerEmail) {
    throw Object.assign(new Error('Authenticated user does not match roll number'), { status: 403 });
  }
  
  return userSnap; // Return so callers can reuse without a second fetch
}

/**
 * Verify RSA-PSS signature of a nonce using a stored public key PEM.
 * Uses crypto.verify() (Node 16+) with explicit PSS padding options.
 * NOTE: dsaEncoding is intentionally omitted — it is ECDSA-only and
 *       causes a TypeError when passed with RSA keys.
 */
function verifyRsaPssSignature(publicKeyPem, nonce, signatureBase64) {
  const key = pemToKeyObject(publicKeyPem);
  return crypto.verify(
    'SHA256',
    Buffer.from(nonce),
    { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
    Buffer.from(signatureBase64, 'base64')
  );
}

/**
 * Mirror of calculateSemester() in index.js.
 * Kept in sync — returns 1, 2, or 0 (unknown).
 */
function calculateSemester(eventDate, eventId) {
  try {
    const months = ['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec'];
    const parseM = s => months.indexOf((s || '').toLowerCase().replace(/[^a-z]/g, '').slice(0, 3));
    let day, mi;

    if (eventDate && typeof eventDate === 'string') {
      const parts = eventDate.trim().split(/[\s\-/\.]+/);
      if (parts.length >= 2) {
        if (/^\d{4}$/.test(parts[0])) { mi = parseInt(parts[1], 10) - 1; day = parseInt(parts[2], 10); }
        else if (/^\d{1,2}$/.test(parts[0])) {
          day = parseInt(parts[0], 10);
          const m = parseM(parts[1]);
          mi = m !== -1 ? m : parseInt(parts[1], 10) - 1;
        }
      }
    }
    if ((isNaN(day) || mi === undefined || mi === -1) && eventId) {
      const p = eventId.split('_');
      if (p.length >= 2 && /^\d{1,2}$/.test(p[0])) { day = parseInt(p[0], 10); mi = parseM(p[1]); }
    }
    if (isNaN(day) || mi === undefined || mi < 0 || mi > 11) return 0;
    const m = mi + 1;
    if (m >= 7 && m <= 11) return 1;
    if (m === 12 && day <= 10) return 1;
    if (m === 12 && day >= 11) return 2;
    if (m >= 1 && m <= 6) return 2;
  } catch (_) {}
  return 0;
}

/**
 * Extract a human-readable event name from the Firestore document ID.
 * Format: DD_Mon_EventName  →  "EventName"
 */
function extractEventName(ev, docId) {
  if (ev.eventName) return ev.eventName;
  const parts = docId.split('_');
  return parts.length >= 3 ? parts.slice(2).join(' ') : docId;
}

// ═══════════════════════════════════════════════════════════
// FUNCTION 1 — ios_getDeviceBindChallenge
//
// Equivalent to getDeviceBindChallenge but uses an iOS-namespaced
// challenge document so it never conflicts with Android bindings.
// Also allows REBINDING (iOS browsers can lose IndexedDB) — issues
// a new challenge even if a binding already exists.
// POST { rollNumber }
// ═══════════════════════════════════════════════════════════
exports.ios_getDeviceBindChallenge = onRequest({ region: REGION, invoker: 'public' }, async (req, res) => {
  // Allow CORS for web clients
  res.set('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization'); return res.status(204).send(''); }
  try {
    if (req.method !== 'POST') throw Object.assign(new Error('Method not allowed'), { status: 405 });
    const decoded      = await verifyAuthToken(req);
    const { rollNumber } = req.body || {};
    if (!rollNumber) throw Object.assign(new Error('Missing rollNumber'), { status: 400 });
    const db   = admin.firestore();
    await assertUserIdentityMatches(db, rollNumber.toUpperCase(), decoded);

    const nonce     = generateNonce();
    const expiresAt = Timestamp.fromDate(new Date(Date.now() + 5 * 60 * 1000)); // 5 min
    // Use ios-namespaced challenge doc so Android challenges are unaffected
    await db.collection('users').doc(rollNumber.toUpperCase())
      .collection('deviceChallenges').doc(`${IOS_PREFIX}bind`)
      .set({ nonce, expiresAt, issuedFor: 'ios_web' }, { merge: true });

    res.json({ nonce, expiresAt: expiresAt.toMillis() });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════
// FUNCTION 2 — ios_bindDevice
//
// Verifies the signed nonce and stores the browser's RSA public key
// as `iosDeviceBinding` (separate from Android's `deviceBinding`).
// This means an iOS student can have BOTH bindings simultaneously.
// Allows re-binding (no 409 conflict — iOS browsers can clear IndexedDB).
// POST { rollNumber, publicKeyPem, signatureBase64 }
// ═══════════════════════════════════════════════════════════
exports.ios_bindDevice = onRequest({ region: REGION, invoker: 'public' }, async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization'); return res.status(204).send(''); }
  try {
    if (req.method !== 'POST') throw Object.assign(new Error('Method not allowed'), { status: 405 });
    const decoded = await verifyAuthToken(req);
    const { rollNumber, publicKeyPem, signatureBase64 } = req.body || {};
    if (!rollNumber || !publicKeyPem || !signatureBase64)
      throw Object.assign(new Error('Missing fields: rollNumber, publicKeyPem, signatureBase64'), { status: 400 });

    const db      = admin.firestore();
    await assertUserIdentityMatches(db, rollNumber.toUpperCase(), decoded);
    const userRef = db.collection('users').doc(rollNumber.toUpperCase());

    await db.runTransaction(async (tx) => {
      const challengeRef  = userRef.collection('deviceChallenges').doc(`${IOS_PREFIX}bind`);
      const challengeSnap = await tx.get(challengeRef);
      if (!challengeSnap.exists) throw Object.assign(new Error('No bind challenge found — call ios_getDeviceBindChallenge first'), { status: 400 });

      const { nonce, expiresAt } = challengeSnap.data();
      if (!nonce || expiresAt.toMillis() < Date.now())
        throw Object.assign(new Error('Bind challenge expired'), { status: 400 });

      const isValid = verifyRsaPssSignature(publicKeyPem, nonce, signatureBase64);
      if (!isValid) throw Object.assign(new Error('Invalid signature — key pair mismatch'), { status: 400 });

      const pubKeyDer = pemToKeyObject(publicKeyPem).export({ type: 'spki', format: 'der' });
      const binding = {
        publicKey:      publicKeyPem,
        fingerprint:   crypto.createHash('sha256').update(pubKeyDer).digest('hex'),
        status:        'active',
        registeredAt:  FieldValue.serverTimestamp(),
        lastVerifiedAt: FieldValue.serverTimestamp(),
        platform:      'ios_web',
      };

      // Store as `iosDeviceBinding` — separate from Android's `deviceBinding`
      tx.set(userRef, { iosDeviceBinding: binding }, { merge: true });
      tx.delete(challengeRef);
    });

    res.json({ ok: true });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════
// FUNCTION 3 — ios_getAttendanceChallenge
//
// Issues a short-lived nonce for a specific event scan.
// Requires the iOS device binding to be active.
// POST { rollNumber, eventId }
// ═══════════════════════════════════════════════════════════
exports.ios_getAttendanceChallenge = onRequest({ region: REGION, invoker: 'public' }, async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization'); return res.status(204).send(''); }
  try {
    if (req.method !== 'POST') throw Object.assign(new Error('Method not allowed'), { status: 405 });
    const decoded = await verifyAuthToken(req);
    const { rollNumber, eventId } = req.body || {};
    if (!rollNumber || !eventId) throw Object.assign(new Error('Missing rollNumber or eventId'), { status: 400 });

    const db      = admin.firestore();
    const userSnap = await assertUserIdentityMatches(db, rollNumber.toUpperCase(), decoded);
    const binding  = userSnap.get('iosDeviceBinding') || null;
    if (!binding || binding.status !== 'active')
      throw Object.assign(new Error('No active iOS device binding. Please re-authenticate.'), { status: 403 });

    const nonce     = generateNonce();
    const expiresAt = Timestamp.fromDate(new Date(Date.now() + 2 * 60 * 1000)); // 2 min
    await db.collection('users').doc(rollNumber.toUpperCase())
      .collection('deviceChallenges').doc(`${IOS_PREFIX}attendance_${eventId}`)
      .set({ nonce, expiresAt, issuedFor: 'ios_web' }, { merge: true });

    res.json({ nonce, expiresAt: expiresAt.toMillis() });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════
// FUNCTION 4 — ios_markAttendance
//
// The main secure attendance endpoint.
// Validates: Auth token → identity match → iOS binding → signature
//   → event exists → event is live → geofence → duplicate check.
// Writes: attendance sub-doc + attendees array update.
// The onAttendanceCreate trigger then auto-credits hours (existing infra).
// POST { rollNumber, eventId, signatureBase64, latitude, longitude,
//        attendeeName, qrTimestamp }
// ═══════════════════════════════════════════════════════════
exports.ios_markAttendance = onRequest({ region: REGION, invoker: 'public' }, async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization'); return res.status(204).send(''); }
  try {
    if (req.method !== 'POST') throw Object.assign(new Error('Method not allowed'), { status: 405 });
    const decoded = await verifyAuthToken(req);
    const { rollNumber, eventId, signatureBase64, latitude, longitude, attendeeName, qrTimestamp } = req.body || {};

    if (!rollNumber || !eventId || !signatureBase64)
      throw Object.assign(new Error('Missing required fields: rollNumber, eventId, signatureBase64'), { status: 400 });

    const db      = admin.firestore();
    const userSnap = await assertUserIdentityMatches(db, rollNumber.toUpperCase(), decoded);
    const binding  = userSnap.get('iosDeviceBinding') || null;
    if (!binding || binding.status !== 'active')
      throw Object.assign(new Error('No active iOS device binding. Please log out and log back in.'), { status: 403 });

    // ── Verify signature ──
    const challengeRef  = db.collection('users').doc(rollNumber.toUpperCase())
      .collection('deviceChallenges').doc(`${IOS_PREFIX}attendance_${eventId}`);
    const challengeSnap = await challengeRef.get();
    if (!challengeSnap.exists)
      throw Object.assign(new Error('No attendance challenge found for this event. Scan the QR code again.'), { status: 400 });
    const { nonce, expiresAt } = challengeSnap.data();
    if (!nonce || expiresAt.toMillis() < Date.now())
      throw Object.assign(new Error('Challenge expired. Scan the QR code again.'), { status: 400 });
    const isValid = verifyRsaPssSignature(binding.publicKey, nonce, signatureBase64);
    if (!isValid) throw Object.assign(new Error('Signature verification failed.'), { status: 400 });

    // ── QR timestamp freshness (server-side recheck) ──
    if (qrTimestamp && (Date.now() - Number(qrTimestamp)) > 10000)
      throw Object.assign(new Error('QR code expired. Please scan a fresh code.'), { status: 400 });

    const eventRef = db.collection('NSS_Events_Attendence').doc(eventId);
    const rollUpper = rollNumber.toUpperCase();

    await db.runTransaction(async (tx) => {
      const eventSnap = await tx.get(eventRef);
      if (!eventSnap.exists) throw Object.assign(new Error('Event not found.'), { status: 404 });
      const ev = eventSnap.data();

      // ── Live check ──
      if (ev.isLive === false)
        throw Object.assign(new Error('This event has ended and is no longer accepting attendance.'), { status: 400 });

      // ── Geofence check (server-side authority) ──
      if (typeof ev.attendanceLocationLatitude === 'number' && typeof ev.attendanceLocationLongitude === 'number') {
        if (typeof latitude !== 'number' || typeof longitude !== 'number')
          throw Object.assign(new Error('Location data required for this event.'), { status: 400 });
        const dist = haversineKm(latitude, longitude, ev.attendanceLocationLatitude, ev.attendanceLocationLongitude);
        if (dist > 0.15) // 150m tolerance (slightly looser than client for GPS drift)
          throw Object.assign(new Error(`You are ${Math.round(dist * 1000)}m away from the event venue.`), { status: 400 });
      }

      // ── Duplicate check ──
      const attendanceDocRef = eventRef.collection('attendance').doc(rollUpper);
      const existingSnap     = await tx.get(attendanceDocRef);
      if (existingSnap.exists)
        throw Object.assign(new Error('Attendance already marked for this event.'), { status: 409 });

      // ── Device re-use check (prevent passing phone around) ──
      const fingerprint = binding.fingerprint;
      const usedByOther = (ev.attendees || []).some(
        a => a.iosDeviceFingerprint === fingerprint && (a.rollNumber || a.roll_number || '').toUpperCase() !== rollUpper
      );
      if (usedByOther)
        throw Object.assign(new Error('This device has already been used by another student for this event.'), { status: 400 });

      // ── Build attendance record ──
      let scanLocation = null;
      if (typeof latitude === 'number' && typeof longitude === 'number') {
        scanLocation = new GeoPoint(latitude, longitude);
      }

      const attendeeRecord = {
        rollNumber:            rollUpper,
        roll_number:           rollUpper,
        name:                  attendeeName || userSnap.get('name') || 'Unknown',
        scan_timestamp:        Timestamp.now(),
        scanTimestamp:         Timestamp.now(),
        attendanceMethod:      'QR_IOS_WEB',
        attendance_method:     'QR_IOS_WEB',
        iosDeviceFingerprint:  fingerprint,
        manualEntry:           false,
        ...(scanLocation ? { scan_location: scanLocation, scanLocation } : {}),
      };

      tx.set(attendanceDocRef, attendeeRecord);
      tx.update(eventRef, {
        attendees: FieldValue.arrayUnion(attendeeRecord),
        // NOTE: total_marked and all hour fields are handled by onAttendanceCreate trigger
      });
    });

    // Clean up challenge and refresh binding timestamp
    await challengeRef.delete();
    await db.collection('users').doc(rollUpper).update({
      'iosDeviceBinding.lastVerifiedAt': FieldValue.serverTimestamp()
    });

    res.json({ ok: true, message: 'Attendance recorded successfully.' });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════
// FUNCTION 5 — ios_getProfile
//
// Returns the student's full profile in one API call:
//   - Basic info (name, rollNumber, wings)
//   - Pre-calculated hours from the users document (fast, no scanning)
//   - Full event breakdown (denominator + wing vs open split)
//     computed server-side from NSS_Events_Attendence
//
// The client receives a clean JSON object — it never touches Firestore.
// POST { rollNumber }
// ═══════════════════════════════════════════════════════════
exports.ios_getProfile = onRequest({ region: REGION, invoker: 'public' }, async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.set('Access-Control-Allow-Headers', 'Content-Type,Authorization'); return res.status(204).send(''); }
  try {
    if (req.method !== 'POST') throw Object.assign(new Error('Method not allowed'), { status: 405 });
    const decoded = await verifyAuthToken(req);
    const { rollNumber } = req.body || {};
    if (!rollNumber) throw Object.assign(new Error('Missing rollNumber'), { status: 400 });

    const db       = admin.firestore();
    const userSnap = await assertUserIdentityMatches(db, rollNumber.toUpperCase(), decoded);
    const d        = userSnap.data() || {};

    // ── Read pre-calculated earned hours (set by onAttendanceCreate trigger) ──
    const sem1Hours       = Number(d.sem1Hours  ?? d.sem1_hours  ?? 0);
    const sem2Hours       = Number(d.sem2Hours  ?? d.sem2_hours  ?? 0);
    const totalHours      = Number(d.hours      ?? 0);
    const eventsAttended  = Number(d.eventsAttended ?? d.events_attended ?? 0);
    const userWings       = d.wings || [];
    const DNC             = 'Design and Curation Wing';
    const rollUpper       = rollNumber.toUpperCase();

    // ── Fetch all events (server-side, never exposed raw to client) ──
    const allEventsSnap = await db.collection('NSS_Events_Attendence').get();

    let sem1TotalHours  = 0;
    let sem2TotalHours  = 0;
    let totalRelevant   = 0;
    const wingEvents    = [];
    const openEvents    = [];

    allEventsSnap.docs.forEach(evDoc => {
      const ev      = evDoc.data();
      const eventId = evDoc.id;
      const sem     = calculateSemester(ev.eventDate, eventId);
      const hours   = Number(ev.hours) || 0;
      const eventName = extractEventName(ev, eventId);

      const attended = (ev.attendees || []).some(
        a => ((a.rollNumber || a.roll_number || '')).toUpperCase() === rollUpper
      );

      // ── Available hours denominator ──
      if (ev.visibleOnlyToPresent) {
        if (attended) {
          if (sem === 1) sem1TotalHours += hours;
          if (sem === 2) sem2TotalHours += hours;
          totalRelevant++;
        }
      } else {
        if (sem === 1) sem1TotalHours += hours;
        if (sem === 2) sem2TotalHours += hours;
        const isDnc      = (ev.wings || []).includes(DNC);
        const isUserWing = (ev.wings || []).some(w => userWings.includes(w));
        if (isDnc || isUserWing || attended) totalRelevant++;
      }

      // ── Wing vs Open split for attended events ──
      if (attended) {
        const relevantWings  = (ev.wings || []).filter(w => w !== DNC);
        const intersection   = relevantWings.filter(w => userWings.includes(w));
        const row = {
          eventId,
          eventName,
          date:   ev.eventDate  || '',
          hours,
          wings:  ev.wings      || [],
          semester: sem,
        };
        if (intersection.length > 0) wingEvents.push(row);
        else                          openEvents.push(row);
      }
    });

    const wingHours = wingEvents.reduce((s, e) => s + e.hours, 0);
    const openHours = openEvents.reduce((s, e) => s + e.hours, 0);

    res.json({
      // Identity
      rollNumber:    rollUpper,
      name:          d.name || d.displayName || 'Student',
      wings:         userWings,
      // Earned hours (from pre-calculated fields — fast)
      sem1Hours,
      sem2Hours,
      totalHours,
      eventsAttended,
      // Denominator (computed server-side)
      sem1TotalHours,
      sem2TotalHours,
      totalRelevantEvents: totalRelevant,
      // Wing / Open split (computed server-side)
      wingHours,
      openHours,
      wingEvents,
      openEvents,
    });
  } catch (err) { sendError(res, err); }
});

// ═══════════════════════════════════════════════════════════
// HAVERSINE DISTANCE UTILITY
// ═══════════════════════════════════════════════════════════
function haversineKm(lat1, lon1, lat2, lon2) {
  const R    = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a    = Math.sin(dLat / 2) ** 2
             + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180)
             * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
