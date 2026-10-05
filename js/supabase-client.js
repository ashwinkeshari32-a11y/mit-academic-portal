/**
 * ============================================================================
 * MIT ACADEMIC PORTAL — SUPABASE CLIENT INITIALIZATION
 * File: js/supabase-client.js
 *
 * SECURITY POLICY:
 * - Uses ONLY public Supabase URL and public Anon/Publishable key.
 * - NEVER embeds service_role keys, database passwords, or private secrets.
 * - All authorization is enforced server-side via PostgreSQL RLS policies.
 * ============================================================================
 */
(function (global) {
  'use strict';

  const AUTH_STORAGE_KEY = 'sb_mit_portal_auth_session';
  const REMEMBER_PREF_KEY = 'mit_portal_remember_pref';

  function resolveSupabaseUrl() {
    if (global.__SUPABASE_CONFIG__ && global.__SUPABASE_CONFIG__.url) {
      return global.__SUPABASE_CONFIG__.url.replace(/\/+$/, '');
    }
    if (global.location && (global.location.protocol === 'http:' || global.location.protocol === 'https:')) {
      return global.location.origin;
    }
    return 'http://localhost:3000';
  }

  function resolveSupabaseAnonKey() {
    if (global.__SUPABASE_CONFIG__ && global.__SUPABASE_CONFIG__.anonKey) {
      return global.__SUPABASE_CONFIG__.anonKey;
    }
    // Public publishable anon key (RLS enforced on all tables)
    return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0.public-anon-key';
  }

  const SUPABASE_URL = resolveSupabaseUrl();
  const SUPABASE_ANON_KEY = resolveSupabaseAnonKey();

  // Internal session storage helper (respects Remember Me preference)
  function loadStoredSession() {
    try {
      const rawSession = sessionStorage.getItem(AUTH_STORAGE_KEY) || localStorage.getItem(AUTH_STORAGE_KEY);
      if (!rawSession) return null;
      const parsed = JSON.parse(rawSession);
      if (!parsed || !parsed.access_token) return null;
      const nowSec = Math.floor(Date.now() / 1000);
      if (parsed.expires_at && nowSec >= parsed.expires_at) {
        clearStoredSession();
        return null;
      }
      return parsed;
    } catch (e) {
      return null;
    }
  }

  function saveStoredSession(session, rememberMe = true) {
    try {
      const serialized = JSON.stringify(session);
      sessionStorage.setItem(AUTH_STORAGE_KEY, serialized);
      if (rememberMe) {
        localStorage.setItem(AUTH_STORAGE_KEY, serialized);
      } else {
        localStorage.removeItem(AUTH_STORAGE_KEY);
      }
    } catch (e) {}
  }

  function clearStoredSession() {
    try {
      sessionStorage.removeItem(AUTH_STORAGE_KEY);
      localStorage.removeItem(AUTH_STORAGE_KEY);
    } catch (e) {}
  }

  const authListeners = new Set();
  function notifyAuthListeners(event, session) {
    authListeners.forEach(cb => {
      try {
        cb(event, session);
      } catch (e) {}
    });
  }

  function buildHeaders(extraHeaders = {}) {
    const session = loadStoredSession();
    const headers = {
      'Content-Type': 'application/json',
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${session ? session.access_token : SUPABASE_ANON_KEY}`,
      ...extraHeaders
    };
    return headers;
  }

  // PostgREST Query Builder compatible with @supabase/supabase-js v2
  class PostgrestQueryBuilder {
    constructor(table) {
      this.table = table;
      this.method = 'GET';
      this.queryParams = new URLSearchParams();
      this.queryParams.set('select', '*');
      this.bodyPayload = null;
      this.preferHeaders = [];
      this.acceptHeader = 'application/json';
    }

    select(columns = '*') {
      const cleaned = String(columns).replace(/\s+/g, '');
      this.queryParams.set('select', cleaned || '*');
      if (this.method === 'POST' || this.method === 'PATCH' || this.method === 'DELETE') {
        if (!this.preferHeaders.includes('return=representation')) {
          this.preferHeaders.push('return=representation');
        }
      }
      return this;
    }

    insert(values) {
      this.method = 'POST';
      this.bodyPayload = values;
      if (!this.preferHeaders.includes('return=representation')) {
        this.preferHeaders.push('return=representation');
      }
      return this;
    }

    upsert(values, options = {}) {
      this.method = 'POST';
      this.bodyPayload = values;
      if (!this.preferHeaders.includes('return=representation')) {
        this.preferHeaders.push('return=representation');
      }
      if (!this.preferHeaders.includes('resolution=merge-duplicates')) {
        this.preferHeaders.push('resolution=merge-duplicates');
      }
      if (options.onConflict) {
        this.queryParams.set('on_conflict', options.onConflict);
      }
      return this;
    }

    update(values) {
      this.method = 'PATCH';
      this.bodyPayload = values;
      if (!this.preferHeaders.includes('return=representation')) {
        this.preferHeaders.push('return=representation');
      }
      return this;
    }

    delete() {
      this.method = 'DELETE';
      if (!this.preferHeaders.includes('return=representation')) {
        this.preferHeaders.push('return=representation');
      }
      return this;
    }

    eq(column, value) {
      this.queryParams.append(column, `eq.${value}`);
      return this;
    }

    neq(column, value) {
      this.queryParams.append(column, `neq.${value}`);
      return this;
    }

    gt(column, value) {
      this.queryParams.append(column, `gt.${value}`);
      return this;
    }

    gte(column, value) {
      this.queryParams.append(column, `gte.${value}`);
      return this;
    }

    lt(column, value) {
      this.queryParams.append(column, `lt.${value}`);
      return this;
    }

    lte(column, value) {
      this.queryParams.append(column, `lte.${value}`);
      return this;
    }

    ilike(column, pattern) {
      this.queryParams.append(column, `ilike.${pattern}`);
      return this;
    }

    in(column, valuesArray) {
      const list = (valuesArray || []).join(',');
      this.queryParams.append(column, `in.(${list})`);
      return this;
    }

    is(column, value) {
      this.queryParams.append(column, `is.${value}`);
      return this;
    }

    order(column, { ascending = true } = {}) {
      const dir = ascending ? 'asc' : 'desc';
      const existing = this.queryParams.get('order');
      this.queryParams.set('order', existing ? `${existing},${column}.${dir}` : `${column}.${dir}`);
      return this;
    }

    limit(count) {
      this.queryParams.set('limit', String(count));
      return this;
    }

    single() {
      this.acceptHeader = 'application/vnd.pgrst.object+json';
      return this;
    }

    maybeSingle() {
      this._maybeSingle = true;
      this.limit(1);
      return this;
    }

    async _execute() {
      const url = `${SUPABASE_URL}/rest/v1/${this.table}?${this.queryParams.toString()}`;
      const extraHeaders = { Accept: this.acceptHeader };
      if (this.preferHeaders.length > 0) {
        extraHeaders.Prefer = this.preferHeaders.join(',');
      }

      try {
        const response = await fetch(url, {
          method: this.method,
          headers: buildHeaders(extraHeaders),
          body: this.bodyPayload !== null ? JSON.stringify(this.bodyPayload) : undefined
        });

        let payload = null;
        const text = await response.text();
        if (text) {
          try {
            payload = JSON.parse(text);
          } catch (e) {
            payload = text;
          }
        }

        if (!response.ok) {
          return {
            data: null,
            error: {
              status: response.status,
              code: payload?.code || String(response.status),
              message: payload?.message || payload?.error_description || payload?.error || 'Database request failed',
              details: payload?.details || null
            }
          };
        }

        if (this._maybeSingle) {
          const row = Array.isArray(payload) ? (payload[0] || null) : payload;
          return { data: row, error: null };
        }

        return { data: payload, error: null };
      } catch (netErr) {
        return {
          data: null,
          error: {
            status: 0,
            code: 'NETWORK_ERROR',
            message: 'Unable to reach the academic database server. Please check your connection and try again.'
          }
        };
      }
    }

    then(onFulfilled, onRejected) {
      return this._execute().then(onFulfilled, onRejected);
    }
  }

  const supabaseClient = {
    supabaseUrl: SUPABASE_URL,
    auth: {
      async signUp({ email, password, options = {} }) {
        try {
          const response = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify({
              email,
              password,
              data: options.data || {}
            })
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok) {
            return {
              data: { user: null, session: null },
              error: {
                status: response.status,
                code: payload.code || payload.error || 'signup_failed',
                message: payload.message || payload.msg || payload.error_description || 'Unable to create account.'
              }
            };
          }
          const session = payload.session || (payload.access_token ? {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token,
            expires_in: payload.expires_in,
            expires_at: payload.expires_at,
            token_type: payload.token_type || 'bearer',
            user: payload.user
          } : null);
          if (session) {
            saveStoredSession(session, false);
            notifyAuthListeners('SIGNED_IN', session);
          }
          return {
            data: { user: payload.user || session?.user || null, session },
            error: null
          };
        } catch (err) {
          return {
            data: { user: null, session: null },
            error: { status: 0, code: 'NETWORK_ERROR', message: 'Network error while creating account.' }
          };
        }
      },

      async signInWithPassword({ email, password, rememberMe = true }) {
        try {
          const response = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify({ email, password })
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok || !payload.access_token) {
            return {
              data: { user: null, session: null },
              error: {
                status: response.status,
                code: payload.error || 'invalid_credentials',
                message: payload.error_description || payload.message || 'Invalid ID or password.'
              }
            };
          }
          const session = {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token,
            expires_in: payload.expires_in,
            expires_at: payload.expires_at,
            token_type: payload.token_type || 'bearer',
            user: payload.user
          };
          saveStoredSession(session, rememberMe);
          notifyAuthListeners('SIGNED_IN', session);
          return { data: { user: payload.user, session }, error: null };
        } catch (err) {
          return {
            data: { user: null, session: null },
            error: { status: 0, code: 'NETWORK_ERROR', message: 'Unable to reach authentication service.' }
          };
        }
      },

      async signInWithDemoPreset(presetKey, rememberMe = false) {
        try {
          const response = await fetch(`${SUPABASE_URL}/auth/v1/demo-session`, {
            method: 'POST',
            headers: buildHeaders(),
            body: JSON.stringify({ preset: presetKey })
          });
          const payload = await response.json().catch(() => ({}));
          if (!response.ok || !payload.access_token) {
            return {
              data: null,
              error: { message: payload.message || 'Demo preset unavailable.' }
            };
          }
          const session = {
            access_token: payload.access_token,
            refresh_token: payload.refresh_token,
            expires_in: payload.expires_in,
            expires_at: payload.expires_at,
            token_type: payload.token_type || 'bearer',
            user: payload.user
          };
          saveStoredSession(session, rememberMe);
          notifyAuthListeners('SIGNED_IN', session);
          return { data: { ...payload, session }, error: null };
        } catch (err) {
          return { data: null, error: { message: 'Unable to reach demo authentication endpoint.' } };
        }
      },

      async signOut() {
        const session = loadStoredSession();
        if (session) {
          try {
            await fetch(`${SUPABASE_URL}/auth/v1/logout`, {
              method: 'POST',
              headers: buildHeaders()
            });
          } catch (e) {}
        }
        clearStoredSession();
        notifyAuthListeners('SIGNED_OUT', null);
        return { error: null };
      },

      async getSession() {
        const session = loadStoredSession();
        return { data: { session }, error: null };
      },

      async getUser() {
        const session = loadStoredSession();
        if (!session) {
          return { data: { user: null }, error: null };
        }
        try {
          const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            method: 'GET',
            headers: buildHeaders()
          });
          if (!response.ok) {
            clearStoredSession();
            notifyAuthListeners('SIGNED_OUT', null);
            return {
              data: { user: null },
              error: { status: response.status, message: 'Session expired. Please sign in again.' }
            };
          }
          const user = await response.json();
          return { data: { user }, error: null };
        } catch (err) {
          return {
            data: { user: session.user || null },
            error: { status: 0, code: 'NETWORK_ERROR', message: 'Unable to verify session.' }
          };
        }
      },

      onAuthStateChange(callback) {
        if (typeof callback === 'function') {
          authListeners.add(callback);
        }
        return {
          data: {
            subscription: {
              unsubscribe: () => authListeners.delete(callback)
            }
          }
        };
      }
    },

    from(table) {
      return new PostgrestQueryBuilder(table);
    },

    async rpc(fnName, params = {}) {
      try {
        const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fnName}`, {
          method: 'POST',
          headers: buildHeaders(),
          body: JSON.stringify(params)
        });
        const payload = await response.json().catch(() => null);
        if (!response.ok) {
          return {
            data: null,
            error: {
              status: response.status,
              message: payload?.message || 'RPC execution failed'
            }
          };
        }
        return { data: payload, error: null };
      } catch (err) {
        return {
          data: null,
          error: { status: 0, code: 'NETWORK_ERROR', message: 'Network error during RPC call.' }
        };
      }
    }
  };

  global.supabaseClient = supabaseClient;
  global.REMEMBER_PREF_KEY = REMEMBER_PREF_KEY;
})(typeof window !== 'undefined' ? window : globalThis);
