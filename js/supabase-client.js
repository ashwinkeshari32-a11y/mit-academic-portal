/**
 * ============================================================================
 * MIT ACADEMIC PORTAL — SUPABASE CLIENT INITIALIZATION
 * File: js/supabase-client.js
 *
 * ARCHITECTURE & SECURITY POLICY:
 * - Uses ONLY public Supabase URL and public Anon/Publishable key.
 * - NEVER embeds service_role keys, database passwords, or private secrets.
 * - NEVER stores academic data (students, faculty, grades, attendance,
 *   notices, timetables, or passwords) in localStorage.
 * - All data operations execute against the shared Supabase / PostgreSQL
 *   backend with Row Level Security (RLS) enforcement.
 * - Provides Supabase Realtime channel subscriptions (`postgres_changes`)
 *   so newly registered students and academic updates sync live across
 *   authorized browsers and devices.
 * ============================================================================
 */
(function (global) {
  'use strict';

  const AUTH_STORAGE_KEY = 'sb_mit_portal_auth_session';
  const SUPABASE_URL_OVERRIDE_KEY = 'mit_portal_supabase_url';

  function resolveSupabaseUrl() {
    if (global.__SUPABASE_CONFIG__ && global.__SUPABASE_CONFIG__.url) {
      return String(global.__SUPABASE_CONFIG__.url).replace(/\/+$/, '');
    }
    try {
      const savedUrl = global.localStorage && global.localStorage.getItem(SUPABASE_URL_OVERRIDE_KEY);
      if (savedUrl && /^https?:\/\//i.test(savedUrl)) {
        return String(savedUrl).trim().replace(/\/+$/, '');
      }
    } catch (e) {}

    if (global.__MIT_SHARED_BACKEND_URL__) {
      return String(global.__MIT_SHARED_BACKEND_URL__).replace(/\/+$/, '');
    }

    if (global.location && (global.location.protocol === 'http:' || global.location.protocol === 'https:')) {
      const host = String(global.location.hostname || '').toLowerCase();
      const port = String(global.location.port || '');
      // If opened via VS Code Live Server (e.g. :5500 / :5501 / :8080), route to the local Node/Supabase backend on :3000
      if ((host === 'localhost' || host === '127.0.0.1') && (port === '5500' || port === '5501' || port === '8080')) {
        return `http://${host}:3000`;
      }
      return global.location.origin.replace(/\/+$/, '');
    }

    return 'http://localhost:3000';
  }

  function resolveSupabaseAnonKey() {
    if (global.__SUPABASE_CONFIG__ && global.__SUPABASE_CONFIG__.anonKey) {
      return global.__SUPABASE_CONFIG__.anonKey;
    }
    return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIn0.public-anon-key';
  }

  let SUPABASE_URL = resolveSupabaseUrl();
  const SUPABASE_ANON_KEY = resolveSupabaseAnonKey();

  // Session token storage helper (stores ONLY the Supabase Auth JWT session token, never academic data or passwords)
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
    return {
      'Content-Type': 'application/json',
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${session ? session.access_token : SUPABASE_ANON_KEY}`,
      ...extraHeaders
    };
  }

  // ==========================================================================
  // 1. SUPABASE AUTHENTICATION CLIENT (auth.*)
  // ==========================================================================
  const auth = {
    async signUp({ email, password, options = {} }) {
      SUPABASE_URL = resolveSupabaseUrl();
      try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
          method: 'POST',
          headers: buildHeaders(),
          body: JSON.stringify({
            email,
            password,
            data: options.data || {}
          })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          return {
            data: { user: null, session: null },
            error: {
              message: data.msg || data.message || data.error_description || 'Registration failed.',
              status: res.status,
              code: data.code || 'auth_signup_error'
            }
          };
        }
        const sessionObj = data.access_token ? {
          access_token: data.access_token,
          refresh_token: data.refresh_token,
          expires_in: data.expires_in || 86400,
          expires_at: data.expires_at || (Math.floor(Date.now() / 1000) + 86400),
          token_type: 'bearer',
          user: data.user
        } : (data.session || null);

        if (sessionObj) {
          saveStoredSession(sessionObj, false);
          notifyAuthListeners('SIGNED_IN', sessionObj);
        }
        return {
          data: {
            user: data.user || (sessionObj ? sessionObj.user : null),
            session: sessionObj
          },
          error: null
        };
      } catch (err) {
        return {
          data: { user: null, session: null },
          error: { message: 'Network error while connecting to authentication service.', status: 0, code: 'NETWORK_ERROR' }
        };
      }
    },

    async signInWithPassword({ email, password, rememberMe = true }) {
      SUPABASE_URL = resolveSupabaseUrl();
      try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
          method: 'POST',
          headers: buildHeaders(),
          body: JSON.stringify({ email, password })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.access_token) {
          return {
            data: { user: null, session: null },
            error: {
              message: data.error_description || data.msg || data.message || 'Invalid login credentials',
              status: res.status,
              code: data.code || 'invalid_credentials'
            }
          };
        }
        const sessionObj = {
          access_token: data.access_token,
          refresh_token: data.refresh_token,
          expires_in: data.expires_in || 86400,
          expires_at: data.expires_at || (Math.floor(Date.now() / 1000) + (data.expires_in || 86400)),
          token_type: data.token_type || 'bearer',
          user: data.user
        };
        saveStoredSession(sessionObj, rememberMe);
        notifyAuthListeners('SIGNED_IN', sessionObj);
        return {
          data: { user: data.user, session: sessionObj },
          error: null
        };
      } catch (err) {
        return {
          data: { user: null, session: null },
          error: { message: 'Unable to reach authentication service. Please check your connection.', status: 0, code: 'NETWORK_ERROR' }
        };
      }
    },

    async signInWithDemoPreset(presetKey, rememberMe = false) {
      SUPABASE_URL = resolveSupabaseUrl();
      try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/demo-session`, {
          method: 'POST',
          headers: buildHeaders(),
          body: JSON.stringify({ preset: presetKey })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.access_token) {
          return {
            data: { user: null, session: null },
            error: { message: data.message || 'Demo login unavailable.', status: res.status }
          };
        }
        const sessionObj = {
          access_token: data.access_token,
          refresh_token: data.refresh_token,
          expires_in: data.expires_in || 86400,
          expires_at: data.expires_at || (Math.floor(Date.now() / 1000) + 86400),
          token_type: 'bearer',
          user: data.user
        };
        saveStoredSession(sessionObj, rememberMe);
        notifyAuthListeners('SIGNED_IN', sessionObj);
        return { data: { user: data.user, session: sessionObj, preset: data }, error: null };
      } catch (err) {
        return { data: { user: null, session: null }, error: { message: 'Unable to reach demo authentication endpoint.' } };
      }
    },

    async signOut() {
      SUPABASE_URL = resolveSupabaseUrl();
      const session = loadStoredSession();
      clearStoredSession();
      if (session && session.access_token) {
        try {
          await fetch(`${SUPABASE_URL}/auth/v1/logout`, {
            method: 'POST',
            headers: {
              apikey: SUPABASE_ANON_KEY,
              Authorization: `Bearer ${session.access_token}`
            }
          });
        } catch (e) {}
      }
      notifyAuthListeners('SIGNED_OUT', null);
      return { error: null };
    },

    async getSession() {
      const session = loadStoredSession();
      return { data: { session }, error: null };
    },

    async getUser() {
      SUPABASE_URL = resolveSupabaseUrl();
      const session = loadStoredSession();
      if (!session || !session.access_token) {
        return { data: { user: null }, error: null };
      }
      try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
          method: 'GET',
          headers: buildHeaders()
        });
        if (!res.ok) {
          if (res.status === 401 || res.status === 403) {
            clearStoredSession();
          }
          return { data: { user: null }, error: { message: 'Session expired or invalid.', status: res.status } };
        }
        const user = await res.json();
        return { data: { user }, error: null };
      } catch (err) {
        return { data: { user: session.user || null }, error: null };
      }
    },

    onAuthStateChange(callback) {
      if (typeof callback === 'function') {
        authListeners.add(callback);
      }
      return {
        data: {
          subscription: {
            unsubscribe() {
              authListeners.delete(callback);
            }
          }
        }
      };
    }
  };

  // ==========================================================================
  // 2. POSTGREST QUERY BUILDER (from(table).select/insert/update/upsert/delete)
  // ==========================================================================
  class PostgrestQueryBuilder {
    constructor(table) {
      this.table = table;
      this.method = 'GET';
      this.queryParams = new URLSearchParams();
      this.bodyPayload = null;
      this.extraHeaders = {};
      this.expectSingle = false;
      this.expectMaybeSingle = false;
    }

    select(columns = '*') {
      const cleaned = String(columns).replace(/\s+/g, '');
      this.queryParams.set('select', cleaned);
      if (this.method === 'POST' || this.method === 'PATCH' || this.method === 'DELETE') {
        this._appendPrefer('return=representation');
      }
      return this;
    }

    insert(values, options = {}) {
      this.method = 'POST';
      this.bodyPayload = values;
      this._appendPrefer('return=representation');
      if (options.onConflict) {
        this.queryParams.set('on_conflict', options.onConflict);
      }
      return this;
    }

    upsert(values, options = {}) {
      this.method = 'POST';
      this.bodyPayload = values;
      this._appendPrefer('return=representation');
      this._appendPrefer('resolution=merge-duplicates');
      if (options.onConflict) {
        this.queryParams.set('on_conflict', options.onConflict);
      }
      return this;
    }

    update(values) {
      this.method = 'PATCH';
      this.bodyPayload = values;
      this._appendPrefer('return=representation');
      return this;
    }

    delete() {
      this.method = 'DELETE';
      this._appendPrefer('return=representation');
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

    ilike(column, pattern) {
      this.queryParams.append(column, `ilike.${pattern}`);
      return this;
    }

    in(column, valuesArray) {
      const list = (valuesArray || []).map(v => `"${String(v).replace(/"/g, '\\"')}"`).join(',');
      this.queryParams.append(column, `in.(${list})`);
      return this;
    }

    gte(column, value) {
      this.queryParams.append(column, `gte.${value}`);
      return this;
    }

    lte(column, value) {
      this.queryParams.append(column, `lte.${value}`);
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
      this.expectSingle = true;
      return this;
    }

    maybeSingle() {
      this.expectMaybeSingle = true;
      return this;
    }

    _appendPrefer(directive) {
      const current = this.extraHeaders['Prefer'];
      if (!current) {
        this.extraHeaders['Prefer'] = directive;
      } else if (!current.includes(directive)) {
        this.extraHeaders['Prefer'] = `${current},${directive}`;
      }
    }

    async _execute() {
      SUPABASE_URL = resolveSupabaseUrl();
      const qs = this.queryParams.toString();
      const url = `${SUPABASE_URL}/rest/v1/${encodeURIComponent(this.table)}${qs ? '?' + qs : ''}`;
      const headers = buildHeaders(this.extraHeaders);

      if (this.expectSingle) {
        headers['Accept'] = 'application/vnd.pgrst.object+json';
      }

      const fetchOptions = {
        method: this.method,
        headers
      };

      if (this.bodyPayload !== null && this.method !== 'GET') {
        fetchOptions.body = JSON.stringify(this.bodyPayload);
      }

      try {
        const res = await fetch(url, fetchOptions);
        const text = await res.text();
        let parsed = null;
        if (text) {
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = text;
          }
        }

        if (!res.ok) {
          if (this.expectMaybeSingle && res.status === 406) {
            return { data: null, error: null };
          }
          return {
            data: null,
            error: {
              message: (parsed && (parsed.message || parsed.msg || parsed.error)) || `Database request failed (${res.status})`,
              details: parsed && parsed.details,
              hint: parsed && parsed.hint,
              code: (parsed && parsed.code) || String(res.status),
              status: res.status
            }
          };
        }

        if (this.expectMaybeSingle) {
          if (Array.isArray(parsed)) {
            return { data: parsed.length > 0 ? parsed[0] : null, error: null };
          }
          return { data: parsed || null, error: null };
        }

        if (this.expectSingle && Array.isArray(parsed)) {
          if (parsed.length === 0) {
            return { data: null, error: { message: 'Row not found', code: 'PGRST116', status: 406 } };
          }
          return { data: parsed[0], error: null };
        }

        return { data: parsed, error: null };
      } catch (err) {
        return {
          data: null,
          error: {
            message: 'Unable to communicate with the academic database.',
            code: 'NETWORK_ERROR',
            status: 0
          }
        };
      }
    }

    then(onFulfilled, onRejected) {
      return this._execute().then(onFulfilled, onRejected);
    }
  }

  // ==========================================================================
  // 3. RPC INVOCATION HELPER (rpc(fnName, params))
  // ==========================================================================
  async function rpc(fnName, params = {}) {
    SUPABASE_URL = resolveSupabaseUrl();
    try {
      const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${encodeURIComponent(fnName)}`, {
        method: 'POST',
        headers: buildHeaders(),
        body: JSON.stringify(params)
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        return {
          data: null,
          error: {
            message: (data && (data.message || data.msg || data.error)) || 'RPC invocation failed',
            code: (data && data.code) || String(res.status),
            status: res.status
          }
        };
      }
      return { data, error: null };
    } catch (err) {
      return {
        data: null,
        error: { message: 'Network error during RPC call.', code: 'NETWORK_ERROR', status: 0 }
      };
    }
  }

  // ==========================================================================
  // 4. SUPABASE REALTIME CHANNEL ENGINE (channel(name).on('postgres_changes', ...))
  // ==========================================================================
  const activeChannels = new Set();
  let sharedEventSource = null;
  let sharedPollInterval = null;
  let lastSeenCursor = null;

  function dispatchRealtimePayload(payload) {
    if (!payload) return;
    if (typeof payload.cursor === 'number' && lastSeenCursor !== null && payload.cursor <= lastSeenCursor) {
      return;
    }
    if (typeof payload.cursor === 'number') {
      lastSeenCursor = payload.cursor;
    }

    activeChannels.forEach(ch => {
      ch._dispatch(payload);
    });
  }

  async function pollRealtimeEventsOnce() {
    if (activeChannels.size === 0) return;
    SUPABASE_URL = resolveSupabaseUrl();
    try {
      const url = lastSeenCursor === null
        ? `${SUPABASE_URL}/realtime/v1/events`
        : `${SUPABASE_URL}/realtime/v1/events?since=${lastSeenCursor}`;
      const res = await fetch(url, {
        method: 'GET',
        headers: buildHeaders()
      });
      if (!res.ok) return;
      const data = await res.json().catch(() => null);
      if (!data) return;
      if (lastSeenCursor === null) {
        lastSeenCursor = typeof data.cursor === 'number' ? data.cursor : 0;
        return;
      }
      if (Array.isArray(data.events)) {
        data.events.forEach(ev => dispatchRealtimePayload(ev));
      }
      if (typeof data.cursor === 'number' && data.cursor > lastSeenCursor) {
        lastSeenCursor = data.cursor;
      }
    } catch (e) {}
  }

  function ensureRealtimeTransport() {
    if (activeChannels.size === 0) return;
    SUPABASE_URL = resolveSupabaseUrl();

    // 1. SSE stream for instant (<50ms) notifications
    if (!sharedEventSource && typeof global.EventSource === 'function') {
      try {
        const es = new global.EventSource(`${SUPABASE_URL}/realtime/v1/stream`);
        es.onmessage = (evt) => {
          if (!evt || !evt.data) return;
          try {
            const parsed = JSON.parse(evt.data);
            dispatchRealtimePayload(parsed);
          } catch (e) {}
        };
        es.onerror = () => {
          try { es.close(); } catch (e) {}
          sharedEventSource = null;
        };
        sharedEventSource = es;
      } catch (e) {
        sharedEventSource = null;
      }
    }

    // 2. Lightweight cursor polling fallback (every 2.5s) for proxies/tunnels that buffer SSE
    if (!sharedPollInterval && typeof global.setInterval === 'function') {
      pollRealtimeEventsOnce();
      sharedPollInterval = global.setInterval(pollRealtimeEventsOnce, 2500);
    }
  }

  function stopRealtimeTransportIfIdle() {
    if (activeChannels.size > 0) return;
    if (sharedEventSource) {
      try { sharedEventSource.close(); } catch (e) {}
      sharedEventSource = null;
    }
    if (sharedPollInterval && typeof global.clearInterval === 'function') {
      global.clearInterval(sharedPollInterval);
      sharedPollInterval = null;
    }
  }

  class RealtimeChannel {
    constructor(name) {
      this.name = name;
      this.listeners = [];
      this.subscribed = false;
    }

    on(type, filter, callback) {
      if (type === 'postgres_changes' && typeof callback === 'function') {
        this.listeners.push({
          event: String((filter && filter.event) || '*').toUpperCase(),
          schema: String((filter && filter.schema) || 'public').toLowerCase(),
          table: String((filter && filter.table) || '*').toLowerCase(),
          callback
        });
      }
      return this;
    }

    subscribe(statusCallback) {
      this.subscribed = true;
      activeChannels.add(this);
      ensureRealtimeTransport();
      if (typeof statusCallback === 'function') {
        setTimeout(() => statusCallback('SUBSCRIBED'), 0);
      }
      return this;
    }

    unsubscribe() {
      this.subscribed = false;
      activeChannels.delete(this);
      stopRealtimeTransportIfIdle();
      return Promise.resolve('ok');
    }

    _dispatch(payload) {
      if (!this.subscribed) return;
      const evType = String(payload.eventType || '').toUpperCase();
      const schema = String(payload.schema || 'public').toLowerCase();
      const table = String(payload.table || '').toLowerCase();

      this.listeners.forEach(l => {
        if (l.schema !== '*' && l.schema !== schema) return;
        if (l.table !== '*' && l.table !== table) return;
        if (l.event !== '*' && l.event !== evType) return;
        try {
          l.callback(payload);
        } catch (e) {}
      });
    }
  }

  function channel(name = 'portal-realtime') {
    return new RealtimeChannel(name);
  }

  function removeChannel(ch) {
    if (ch && typeof ch.unsubscribe === 'function') {
      return ch.unsubscribe();
    }
    return Promise.resolve('ok');
  }

  // Export global Supabase client instance
  global.supabaseClient = {
    supabaseUrl: SUPABASE_URL,
    auth,
    from(table) {
      return new PostgrestQueryBuilder(table);
    },
    rpc,
    channel,
    removeChannel
  };
})(typeof window !== 'undefined' ? window : globalThis);
