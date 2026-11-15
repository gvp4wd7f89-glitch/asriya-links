const enc = new TextEncoder();
const COOKIE = "asriya_admin";

function b64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function fromB64url(s) {
  const b = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b + "=".repeat((4 - b.length % 4) % 4)), c => c.charCodeAt(0));
}
async function hmac(secret, value) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign","verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}
export async function passwordMatches(password, stored) {
  // Stored format: pbkdf2$iterations$salt_base64url$hash_base64url
  const [scheme, count, saltText, hashText] = (stored || "").split("$");
  if (scheme !== "pbkdf2" || !count || !saltText || !hashText) return false;
  const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:fromB64url(saltText),iterations:Number(count),hash:"SHA-256"},material,256);
  const actual = new Uint8Array(bits), expected = fromB64url(hashText);
  if (actual.length !== expected.length) return false;
  let diff = 0; for (let i=0;i<actual.length;i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}
export async function makeSession(secret) {
  const payload = b64url(enc.encode(JSON.stringify({exp:Date.now()+8*60*60*1000, nonce:crypto.randomUUID()})));
  const sig = b64url(await hmac(secret,payload));
  return payload + "." + sig;
}
export async function validSession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const token = cookie.split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1);
  if (!token || !secret) return false;
  const [payload,sig] = token.split(".");
  if (!payload || !sig) return false;
  const key = await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
  const ok = await crypto.subtle.verify("HMAC",key,fromB64url(sig),enc.encode(payload));
  if (!ok) return false;
  try { return JSON.parse(new TextDecoder().decode(fromB64url(payload))).exp > Date.now(); } catch { return false; }
}
export function cookieHeader(value, maxAge=28800) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
export function originAllowed(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}
