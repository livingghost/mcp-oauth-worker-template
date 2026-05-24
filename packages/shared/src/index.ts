export const OAUTH_SCOPES = ["profile"] as const;

export type OAuthScope = (typeof OAUTH_SCOPES)[number];

export const ADMIN_PERMISSION = "admin";

export const USER_PERMISSIONS = [ADMIN_PERMISSION] as const;

export type UserPermission = (typeof USER_PERMISSIONS)[number];

export const ADMIN_PERMISSIONS = ["admin"] as const satisfies readonly UserPermission[];

export function assertKnownPermissions(permissions: readonly string[]): UserPermission[] {
  const known = new Set<string>(USER_PERMISSIONS);
  const unknown = permissions.map((permission) => permission.trim()).filter((permission) => permission && !known.has(permission));
  if (unknown.length > 0) {
    throw new Error(`Unknown user permission: ${unknown.join(", ")}`);
  }
  return [...new Set(permissions.map((permission) => permission.trim()).filter(Boolean))].sort() as UserPermission[];
}

export interface UserProfile {
  id: string;
  email: string;
  status: "active" | "disabled";
  authzVersion: number;
}

export interface OAuthTokenProps {
  user_id: string;
  authz_version: number;
  client_id: string;
  client_version: number;
  resource: string;
  scope_hash: string;
  consent_id: string;
}

export interface AuthContext {
  user: UserProfile;
  client: {
    id: string;
    version: number;
  };
  permissions: string[];
  resource: string;
  scopes: OAuthScope[];
  scopeHash: string;
  consentId: string;
}

export interface AuthorizationRuntime {
  serverName: string;
  canUseCapability(context: AuthContext, capability: CapabilityRequirement): boolean;
}

export interface CapabilityRequirement {
  name: string;
  kind: "tool" | "resource" | "prompt";
  requiredScopes: OAuthScope[];
  requiredPermissions: string[];
  requiresFreshAuthz: boolean;
  visibility: "listed" | "hidden";
}

export function canonicalizeScopes(scopes: readonly string[]): OAuthScope[] {
  const known = new Set<string>(OAUTH_SCOPES);
  const normalized = [...new Set(scopes.map((scope) => scope.trim()).filter(Boolean))]
    .filter((scope) => known.has(scope))
    .sort();
  return normalized as OAuthScope[];
}

export function assertKnownScopes(scopes: readonly string[]): OAuthScope[] {
  const known = new Set<string>(OAUTH_SCOPES);
  const unknown = scopes.map((scope) => scope.trim()).filter((scope) => scope && !known.has(scope));
  if (unknown.length > 0) {
    throw new Error(`Unknown OAuth scope: ${unknown.join(", ")}`);
  }
  return canonicalizeScopes(scopes);
}

export async function hashScope(scopes: readonly string[]): Promise<string> {
  return sha256Hex(canonicalizeScopes(scopes).join(" "));
}

export function isScopeSubset(requested: readonly string[], granted: readonly string[]): boolean {
  const grantedSet = new Set(canonicalizeScopes(granted));
  return canonicalizeScopes(requested).every((scope) => grantedSet.has(scope));
}

export function parseScopeString(scope: string | undefined | null): OAuthScope[] {
  return canonicalizeScopes((scope ?? "").split(/\s+/));
}

export function formatCanonicalScope(scopes: readonly string[]): string {
  return canonicalizeScopes(scopes).join(" ");
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function normalizeResourceUri(resource: string): string {
  const url = new URL(resource);
  if (url.hash) {
    throw new Error("resource URI must not contain a fragment");
  }
  return url.toString();
}

export function requireMcpResource(resource: string | undefined, expected: string): string {
  if (!resource) {
    throw new Error("resource is required");
  }
  const normalized = normalizeResourceUri(resource);
  const expectedNormalized = normalizeResourceUri(expected);
  if (normalized !== expectedNormalized) {
    throw new Error("resource does not match MCP resource URI");
  }
  return normalized;
}

export function parseBoolean(value: string | undefined, defaultValue = false): boolean {
  if (value === undefined || value === "") {
    return defaultValue;
  }
  return value === "true" || value === "1";
}

export function parseTtlSeconds(
  value: string | undefined,
  defaultValue: number,
  maxValue: number
): number {
  const parsed = Number(value ?? defaultValue);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return defaultValue;
  }
  return Math.min(Math.floor(parsed), maxValue);
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqual(a: string, b: string): boolean {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  const length = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length ^ bBytes.length;
  for (let index = 0; index < length; index += 1) {
    diff |= (aBytes[index] ?? 0) ^ (bBytes[index] ?? 0);
  }
  return diff === 0;
}

export function randomBase64Url(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export async function sealJson(value: unknown, base64UrlKey: string, aad: string): Promise<string> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const key = await importAesGcmKey(base64UrlKey);
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        additionalData: bytesToArrayBuffer(new TextEncoder().encode(aad)),
        iv: bytesToArrayBuffer(nonce),
        name: "AES-GCM"
      },
      key,
      bytesToArrayBuffer(plaintext)
    )
  );
  return `v1.${base64UrlEncode(nonce)}.${base64UrlEncode(ciphertext)}`;
}

export async function unsealJson(value: string, base64UrlKey: string, aad: string): Promise<unknown> {
  const [version, nonceValue, ciphertextValue] = value.split(".");
  if (version !== "v1" || !nonceValue || !ciphertextValue) {
    throw new Error("Invalid sealed payload format");
  }
  const nonce = base64UrlDecode(nonceValue);
  const ciphertext = base64UrlDecode(ciphertextValue);
  if (nonce.byteLength !== 12) {
    throw new Error("Invalid sealed payload nonce");
  }
  const key = await importAesGcmKey(base64UrlKey);
  const plaintext = await crypto.subtle.decrypt(
    {
      additionalData: bytesToArrayBuffer(new TextEncoder().encode(aad)),
      iv: bytesToArrayBuffer(nonce),
      name: "AES-GCM"
    },
    key,
    bytesToArrayBuffer(ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
}

async function importAesGcmKey(base64UrlKey: string): Promise<CryptoKey> {
  const bytes = base64UrlDecode(base64UrlKey.trim());
  if (bytes.byteLength !== 32) {
    throw new Error("Sealing key must be a base64url encoded 256-bit key");
  }
  return crypto.subtle.importKey("raw", bytesToArrayBuffer(bytes), "AES-GCM", false, ["encrypt", "decrypt"]);
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
