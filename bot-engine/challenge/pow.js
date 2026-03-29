/**
 * JZap — Browser-side SHA-256 Proof-of-Work Challenge
 *
 * This script runs a SHA-256 hashing loop in the browser to prove that the
 * client is a real browser (not a simple bot). On success, it sets a cookie
 * with the solution nonce and redirects back to the original URL.
 *
 * No external dependencies — uses the Web Crypto API (SubtleCrypto).
 */
(function () {
  "use strict";

  var TIMEOUT_MS = 30000; // 30 second timeout
  var BATCH_SIZE = 1000;  // hashes per animation frame batch

  /**
   * Convert an ArrayBuffer to a hex string.
   */
  function bufToHex(buf) {
    var bytes = new Uint8Array(buf);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  /**
   * Check if a hex hash has at least `difficulty` leading zero characters.
   */
  function hasLeadingZeros(hexHash, difficulty) {
    for (var i = 0; i < difficulty; i++) {
      if (hexHash[i] !== "0") return false;
    }
    return true;
  }

  /**
   * Set a cookie with the PoW solution.
   */
  function setSolutionCookie(name, value, maxAgeSec) {
    document.cookie =
      name +
      "=" +
      encodeURIComponent(value) +
      "; path=/; max-age=" +
      maxAgeSec +
      "; SameSite=Strict; Secure";
  }

  /**
   * Update the progress display.
   */
  function updateProgress(attempts, startTime) {
    var elapsed = (Date.now() - startTime) / 1000;
    var rate = Math.round(attempts / elapsed);
    var el = document.getElementById("jzap-progress");
    if (el) {
      el.textContent =
        "Checked " +
        attempts.toLocaleString() +
        " hashes (" +
        rate.toLocaleString() +
        " H/s)";
    }
  }

  /**
   * Show the timeout/fallback message.
   */
  function showTimeout() {
    var el = document.getElementById("jzap-status");
    if (el) {
      el.textContent =
        "Verification is taking longer than expected. Please try refreshing the page.";
    }
    var spinner = document.getElementById("jzap-spinner");
    if (spinner) {
      spinner.style.display = "none";
    }
  }

  /**
   * Run the proof-of-work challenge.
   *
   * @param {string} challenge  - The server-provided challenge string.
   * @param {number} difficulty - Number of leading hex zeros required.
   * @param {string} returnUrl  - URL to redirect to on success.
   * @param {string} cookieName - Cookie name for the solution.
   * @param {number} cookieTTL  - Cookie max-age in seconds.
   */
  async function solve(challenge, difficulty, returnUrl, cookieName, cookieTTL) {
    var encoder = new TextEncoder();
    var startTime = Date.now();
    var nonce = 0;
    var timedOut = false;

    // Set timeout
    var timeoutId = setTimeout(function () {
      timedOut = true;
      showTimeout();
    }, TIMEOUT_MS);

    while (!timedOut) {
      // Process a batch of hashes, then yield to the browser
      for (var i = 0; i < BATCH_SIZE; i++) {
        var input = challenge + ":" + nonce;
        var data = encoder.encode(input);
        var hashBuf = await window.crypto.subtle.digest("SHA-256", data);
        var hexHash = bufToHex(hashBuf);

        if (hasLeadingZeros(hexHash, difficulty)) {
          // Success — clear timeout, set cookie, redirect
          clearTimeout(timeoutId);

          var solution = JSON.stringify({
            nonce: nonce,
            hash: hexHash,
            challenge: challenge,
          });

          setSolutionCookie(cookieName || "jzap_pow", solution, cookieTTL || 3600);

          var el = document.getElementById("jzap-status");
          if (el) {
            el.textContent = "Verified. Redirecting...";
          }

          // Brief delay so the user sees the success message
          setTimeout(function () {
            window.location.href = returnUrl || window.location.href;
          }, 300);

          return;
        }

        nonce++;
      }

      // Update progress display and yield to browser
      updateProgress(nonce, startTime);
      await new Promise(function (resolve) {
        requestAnimationFrame(resolve);
      });
    }
  }

  /**
   * Initialize the challenge from page data.
   * Reads parameters from a <script id="jzap-params"> tag or data attributes
   * on the #jzap-challenge element.
   */
  function init() {
    var params = {};

    // Try reading from inline JSON
    var paramsEl = document.getElementById("jzap-params");
    if (paramsEl) {
      try {
        params = JSON.parse(paramsEl.textContent);
      } catch (e) {
        console.error("JZap: Failed to parse challenge params", e);
        return;
      }
    }

    // Try reading from data attributes as fallback
    var challengeEl = document.getElementById("jzap-challenge");
    if (challengeEl && !params.challenge) {
      params.challenge = challengeEl.getAttribute("data-challenge") || "";
      params.difficulty = parseInt(
        challengeEl.getAttribute("data-difficulty") || "4",
        10
      );
      params.returnUrl = challengeEl.getAttribute("data-return-url") || "";
      params.cookieName = challengeEl.getAttribute("data-cookie-name") || "jzap_pow";
      params.cookieTTL = parseInt(
        challengeEl.getAttribute("data-cookie-ttl") || "3600",
        10
      );
    }

    if (!params.challenge) {
      console.error("JZap: No challenge string found");
      return;
    }

    solve(
      params.challenge,
      params.difficulty || 4,
      params.returnUrl || window.location.href,
      params.cookieName || "jzap_pow",
      params.cookieTTL || 3600
    );
  }

  // Start when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
