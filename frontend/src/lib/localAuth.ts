/**
 * TrustShield Local Authentication & Session Service
 * Communicates with the local FastAPI / Python Backend endpoints:
 *   - POST /api/v1/auth/login
 *   - POST /api/v1/auth/register
 *   - GET  /api/v1/auth/me
 * Zero cloud keys or third-party auth services required.
 */

import { API_BASE_URL } from '../config/api';
const TOKEN_KEY = 'trustshield_auth_token_v1';

export interface UserProfile {
  id: string;
  email: string;
  fullName: string;
  role: 'admin' | 'analyst' | 'viewer';
  createdAt?: string;
}

export interface AuthResponse {
  success: boolean;
  token?: string;
  user?: UserProfile;
  error?: string;
}

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // LocalStorage unavailable
  }
}

export function clearStoredToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    // LocalStorage unavailable
  }
}

export async function loginUser(email: string, password: string): Promise<AuthResponse> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (res.ok && data.token) {
      setStoredToken(data.token);
      return { success: true, token: data.token, user: data.user };
    }
    return { success: false, error: data.error || 'Authentication failed' };
  } catch {
    return { success: false, error: 'Could not connect to authentication gateway' };
  }
}

export async function registerUser(email: string, password: string, fullName: string): Promise<AuthResponse> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, fullName }),
    });
    const data = await res.json();
    if (res.ok && data.token) {
      setStoredToken(data.token);
      return { success: true, token: data.token, user: data.user };
    }
    return { success: false, error: data.error || 'Registration failed' };
  } catch {
    return { success: false, error: 'Could not connect to authentication gateway' };
  }
}

export async function getCurrentUser(): Promise<UserProfile | null> {
  const token = getStoredToken();
  if (!token) return null;

  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      const data = await res.json();
      return data.user || null;
    }
  } catch {
    // Gateway offline
  }
  return null;
}

