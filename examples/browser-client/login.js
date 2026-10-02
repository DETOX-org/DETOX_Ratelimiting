/**
 * DETOX Client-Side 0-Cache Shield — Browser Integration Example
 * 
 * Works with React, Vue, Svelte, vanilla JS, or any frontend.
 * Drop this into your login page component.
 */

import { DetoxClientShield } from 'detox-ratelimit/client';

const shield = new DetoxClientShield();

// ─── Login Form Handler ───────────────────────────────────────────────

async function handleLogin(email, password) {
  // ┌─────────────────────────────────────────────────────────────┐
  // │  LAYER 1: 0-Cache Pre-Flight Interception                  │
  // │  Checks localStorage for previously failed credentials     │
  // │  If found → rejects in 0ms. Zero network traffic!          │
  // └─────────────────────────────────────────────────────────────┘
  const cacheCheck = shield.checkLocal0Cache(email, password);

  if (cacheCheck.isCached) {
    showError(cacheCheck.message); // "Login credentials not valid (0-Cache Verified)"
    return;
  }

  // ┌─────────────────────────────────────────────────────────────┐
  // │  LAYER 2: Check local lockout state before network call     │
  // └─────────────────────────────────────────────────────────────┘
  const lockoutState = shield.getLocalLockoutState(email);

  if (lockoutState) {
    showLockoutBanner(lockoutState.remainingSeconds, lockoutState.uniqueKey);
    return;
  }

  // ┌─────────────────────────────────────────────────────────────┐
  // │  Network Request to Server API                              │
  // └─────────────────────────────────────────────────────────────┘
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    if (response.ok && data.success) {
      // ✅ Successful login — purge all client-side security state
      shield.clear0Cache();
      window.location.href = '/dashboard';
      return;
    }

    if (data.isLocked) {
      // 🔒 Server returned lockout — save state for client-side countdown
      shield.saveLocalLockoutState(email, {
        isLocked: true,
        lockedUntil: data.lockedUntil,
        uniqueKey: data.uniqueKey,
      });
      showLockoutBanner(data.remainingSeconds, data.uniqueKey);

      if (data.antiTamperTriggered) {
        showWarning('⚠️ Anti-tamper violation detected. Cooldown has been reset to full 5 minutes.');
      }
      return;
    }

    // ❌ Invalid credentials — store in 0-cache for instant rejection next time
    shield.storeFailedCred0(email, password);
    showError(`Invalid credentials. ${data.remainingAttempts} attempts remaining.`);
  } catch (err) {
    showError('Network error. Please try again.');
  }
}

// ─── On Page Load: Rehydrate Lockout State ────────────────────────────

function initPage() {
  const lockout = shield.getLocalLockoutState();
  if (lockout) {
    showLockoutBanner(lockout.remainingSeconds, lockout.uniqueKey);
    startCountdown(lockout.remainingSeconds);
  }
}

// ─── UI Helpers (replace with your framework's rendering) ─────────────

function showError(message) {
  document.getElementById('error-banner').textContent = message;
  document.getElementById('error-banner').style.display = 'block';
}

function showWarning(message) {
  console.warn(message);
}

function showLockoutBanner(seconds, securityKey) {
  const banner = document.getElementById('lockout-banner');
  banner.innerHTML = `
    <div class="lockout-container">
      <h2>🔒 Account Temporarily Locked</h2>
      <p>Too many failed attempts. Try again in <strong id="countdown">${seconds}</strong> seconds.</p>
      <p class="security-key">Security Token: <code>${securityKey}</code></p>
    </div>
  `;
  banner.style.display = 'block';
  document.getElementById('login-form').style.display = 'none';
  startCountdown(seconds);
}

function startCountdown(seconds) {
  let remaining = seconds;
  const timer = setInterval(() => {
    remaining--;
    const el = document.getElementById('countdown');
    if (el) el.textContent = String(remaining);
    if (remaining <= 0) {
      clearInterval(timer);
      shield.clearLocalLockoutState();
      document.getElementById('lockout-banner').style.display = 'none';
      document.getElementById('login-form').style.display = 'block';
    }
  }, 1000);
}

// Initialize on DOM ready
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', initPage);
}
