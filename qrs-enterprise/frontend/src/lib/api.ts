// API client for QRS Enterprise.
// Uses the DRF token auth: stores the token in localStorage and sends it as
// `Authorization: Token <token>` on every request.

const API_BASE = '/api';

export interface User {
  id: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  is_active: boolean;
}

export interface FieldSchema {
  type: string;
  name: string;
  label: string;
  options?: string[];
  input_rules?: Record<string, unknown>;
  verify_rules?: Record<string, unknown>;
  default?: unknown;
  binding?: 'inline' | 'stripped' | null;
}

export interface ManagedTcert {
  id: number;
  tcert_id: string;
  key_id: string;
  certificate_number: number;
  name: string;
  algorithm: string;
  is_ca: boolean;
  schema: FieldSchema[];
  has_schema: boolean;
  online_endpoint: string;
  created_at: string;
}

export interface SdocRecord {
  id: number;
  sdoc_id: string;
  tcert_id: string;
  signed_by: string | null;
  sdoc_b64: string;
  issued_at: number;
  created_at: string;
}

export interface Grant {
  id: number;
  user: number;
  username: string;
  tcert: number;
  created_at: string;
}

export interface AuditLogEntry {
  id: number;
  username: string | null;
  action: string;
  tcert_id: string | null;
  target: string;
  ip_address: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface ApiKeyInfo {
  id: number;
  name: string;
  key_prefix: string;
  owner: string | null;
  permissions: string[];
  is_active: boolean;
  expires_at: string | null;
  created_at: string;
  last_used_at: string | null;
}

let token: string | null = localStorage.getItem('qrs_token');

export function setToken(t: string | null) {
  token = t;
  if (t) localStorage.setItem('qrs_token', t);
  else localStorage.removeItem('qrs_token');
}

export function getToken() {
  return token;
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };
  if (token) headers['Authorization'] = `Token ${token}`;
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    setToken(null);
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    console.error('[QRS][API] request failed', {
      path,
      method: options.method ?? 'GET',
      status: res.status,
      detail,
    });
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string; user: User }>('/auth/login/', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request('/auth/logout/', { method: 'POST' }),
  me: () => request<User>('/auth/me/'),
  listTcerts: () => request<ManagedTcert[]>('/tcerts/'),
  createTcert: (data: Record<string, unknown>) =>
    request<ManagedTcert>('/tcerts/', { method: 'POST', body: JSON.stringify(data) }),
  getTcert: (id: number) => request<ManagedTcert>(`/tcerts/${id}/`),
  listGrants: (id: number) => request<Grant[]>(`/tcerts/${id}/grants/`),
  addGrant: (id: number, userId: number) =>
    request<Grant>(`/tcerts/${id}/grants/`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId }),
    }),
  removeGrant: (id: number, grantId: number) =>
    request(`/tcerts/${id}/grants/${grantId}/`, { method: 'DELETE' }),
  signSdoc: (id: number, values: Record<string, unknown>) =>
    request<SdocRecord>(`/tcerts/${id}/sign/`, {
      method: 'POST',
      body: JSON.stringify({ values }),
    }),
  attest: (id: number, targetTcertId: string, claims?: Record<string, unknown>) =>
    request<{ statement_id: string; bytes_b64: string }>(`/tcerts/${id}/attest/`, {
      method: 'POST',
      body: JSON.stringify({ target_tcert_id: targetTcertId, claims }),
    }),
  revoke: (id: number, targetTcertId: string, reason?: string) =>
    request<{ statement_id: string; bytes_b64: string }>(`/tcerts/${id}/revoke/`, {
      method: 'POST',
      body: JSON.stringify({ target_tcert_id: targetTcertId, reason }),
    }),
  listSdocs: () => request<SdocRecord[]>('/sdocs/'),
  getSdoc: (sdocId: string) => request<SdocRecord>(`/sdocs/${sdocId}/`),
  verifySdoc: (sdocB64: string) =>
    request<Record<string, string>>('/sdocs/verify/', {
      method: 'POST',
      body: JSON.stringify({ sdoc_b64: sdocB64 }),
    }),
  blockSdoc: (targetSdocId: string, reason?: string) =>
    request<{ statement_id: string; bytes_b64: string }>('/sdocs/block/', {
      method: 'POST',
      body: JSON.stringify({ target_sdoc_id: targetSdocId, reason }),
    }),
  unblockSdoc: (targetSdocId: string, reason?: string) =>
    request<{ statement_id: string; bytes_b64: string }>('/sdocs/unblock/', {
      method: 'POST',
      body: JSON.stringify({ target_sdoc_id: targetSdocId, reason }),
    }),
  listLogs: () => request<AuditLogEntry[]>('/logs/'),
  listApiKeys: () => request<ApiKeyInfo[]>('/api-keys/'),
  createApiKey: (name: string, permissions: string[]) =>
    request<ApiKeyInfo & { key: string }>('/api-keys/', {
      method: 'POST',
      body: JSON.stringify({ name, permissions }),
    }),
  deleteApiKey: (id: number) => request(`/api-keys/${id}/`, { method: 'DELETE' }),
};
