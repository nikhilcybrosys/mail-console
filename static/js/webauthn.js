// Passkey registration / step-up. Options arrive as base64url JSON from python-fido2.
(function () {
  function b64d(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a.buffer; }
  function b64e(buf) { var b = new Uint8Array(buf), s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function csrf() { var m = document.cookie.match(/(?:^|; )csrftoken=([^;]+)/); return m ? m[1] : document.body.getAttribute("data-csrf"); }
  function post(url, body) { return fetch(url, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRFToken": csrf() }, body: JSON.stringify(body || {}) }); }
  function decodeCreate(o) { var p = o.publicKey; p.challenge = b64d(p.challenge); p.user.id = b64d(p.user.id); (p.excludeCredentials || []).forEach(function (c) { c.id = b64d(c.id); }); return o; }
  function decodeGet(o) { var p = o.publicKey; p.challenge = b64d(p.challenge); (p.allowCredentials || []).forEach(function (c) { c.id = b64d(c.id); }); return o; }
  function say(msg) { var el = document.getElementById("wa-status"); if (el) el.textContent = msg; }
  async function register() {
    var r = await post("/passkeys/register/begin/"); if (!r.ok) { say("Sign in again, then retry (recent login required)."); return false; }
    var cred = await navigator.credentials.create(decodeCreate(await r.json()));
    var res = cred.response, name = (document.getElementById("pk-name") || {}).value || "passkey";
    var ok = await post("/passkeys/register/complete/", { id: cred.id, rawId: b64e(cred.rawId), type: cred.type, name: name,
      response: { attestationObject: b64e(res.attestationObject), clientDataJSON: b64e(res.clientDataJSON) }, clientExtensionResults: cred.getClientExtensionResults() });
    return ok.ok;
  }
  async function assert() {
    var r = await post("/step-up/begin/"); if (!r.ok) { say("No passkey registered."); return false; }
    var cred = await navigator.credentials.get(decodeGet(await r.json())), res = cred.response;
    var ok = await post("/step-up/complete/", { id: cred.id, rawId: b64e(cred.rawId), type: cred.type,
      response: { authenticatorData: b64e(res.authenticatorData), clientDataJSON: b64e(res.clientDataJSON), signature: b64e(res.signature), userHandle: res.userHandle ? b64e(res.userHandle) : null },
      clientExtensionResults: cred.getClientExtensionResults() });
    return ok.ok;
  }
  document.addEventListener("click", async function (e) {
    var b = e.target.closest("[data-webauthn]"); if (!b) return;
    e.preventDefault(); say("Waiting for your authenticator…");
    try {
      var ok = b.getAttribute("data-webauthn") === "register" ? await register() : await assert();
      if (ok) { say("Verified."); location.href = b.getAttribute("data-next") || "/"; } else say("Verification failed. Try again.");
    } catch (err) { say("Cancelled or not supported on this device."); }
  });
})();
