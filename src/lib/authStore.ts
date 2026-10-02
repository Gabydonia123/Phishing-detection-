import { UserProfile } from '../types';

const AUTH_STORAGE_KEY = 'phish_guard_user_session_v2';
const USERS_REGISTRY_KEY = 'phish_guard_users_db_v2';
const CREDENTIALS_KEY = 'phish_guard_creds_db_v2';

export interface AuthState {
  currentUser: UserProfile | null;
  isAuthenticated: boolean;
}

export function getStoredSession(): UserProfile | null {
  try {
    const saved = localStorage.getItem(AUTH_STORAGE_KEY);
    if (saved) {
      return JSON.parse(saved);
    }
  } catch (e) {
    console.error('Failed to parse user session', e);
  }
  return null;
}

export function saveSession(user: UserProfile | null): void {
  try {
    if (user) {
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user));
    } else {
      localStorage.removeItem(AUTH_STORAGE_KEY);
    }
  } catch (e) {
    console.error('Failed to write user session', e);
  }
}

export function getRegisteredUsers(): UserProfile[] {
  try {
    const saved = localStorage.getItem(USERS_REGISTRY_KEY);
    if (saved) {
      return JSON.parse(saved);
    }
  } catch (e) {
    console.error('Failed to get registered users', e);
  }
  return [];
}

interface StoredCredential {
  email: string;
  passwordHash: string;
}

function getStoredCredentials(): StoredCredential[] {
  try {
    const saved = localStorage.getItem(CREDENTIALS_KEY);
    if (saved) {
      return JSON.parse(saved);
    }
  } catch (e) {
    console.error('Failed to get credentials', e);
  }
  return [];
}

export function verifyUserLogin(email: string, password: string): { success: boolean; user?: UserProfile; error?: string } {
  const cleanEmail = email.trim().toLowerCase();
  const users = getRegisteredUsers();
  const user = users.find(u => u.email === cleanEmail);

  if (!user) {
    return {
      success: false,
      error: 'No account found with this email. Please create an account before logging in.'
    };
  }

  const credentials = getStoredCredentials();
  const cred = credentials.find(c => c.email === cleanEmail);

  // If password was stored, check it matches
  if (cred && cred.passwordHash !== password) {
    return {
      success: false,
      error: 'Incorrect password. Please try again.'
    };
  }

  saveSession(user);
  return {
    success: true,
    user
  };
}

export function registerNewUser(data: {
  name: string;
  email: string;
  password?: string;
  authProvider: 'google' | 'email';
  role?: string;
  organization?: string;
}): UserProfile {
  const cleanEmail = data.email.trim().toLowerCase();
  const newUser: UserProfile = {
    id: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    name: data.name.trim() || cleanEmail.split('@')[0],
    email: cleanEmail,
    authProvider: data.authProvider,
    role: data.role || 'Security Analyst',
    organization: data.organization || 'Independent Security Researcher',
    avatarUrl: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(data.name || cleanEmail)}&backgroundColor=0284c7`,
    createdAt: new Date().toISOString()
  };

  try {
    const existing = getRegisteredUsers();
    // Check and update or add
    const filtered = existing.filter(u => u.email !== cleanEmail);
    filtered.push(newUser);
    localStorage.setItem(USERS_REGISTRY_KEY, JSON.stringify(filtered));

    // Store credential for authentication check
    if (data.password) {
      const credentials = getStoredCredentials();
      const filteredCreds = credentials.filter(c => c.email !== cleanEmail);
      filteredCreds.push({
        email: cleanEmail,
        passwordHash: data.password
      });
      localStorage.setItem(CREDENTIALS_KEY, JSON.stringify(filteredCreds));
    }
  } catch (e) {
    console.error('Failed to save to users registry', e);
  }

  saveSession(newUser);
  return newUser;
}
