// manage_sys/api/manage_api.js — client dùng chung. Web: cookie phiên + CSRF. App (React Native/JS): truyền {token}.
export class ManageApi {
  constructor({ base = '/manage-sys/api/v1', token = null } = {}) { this.base = base; this.token = token; this.csrf = null; }

  async request(method, path, { body, query } = {}) {
    const url = this.base + path + (query ? '?' + new URLSearchParams(query) : '');
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.token) headers.Authorization = 'Bearer ' + this.token;
    else if (method !== 'GET') {
      if (!this.csrf) this.csrf = (await this.request('GET', '/auth/csrf/')).csrf_token;
      headers['X-CSRFToken'] = this.csrf;
    }
    const res = await fetch(url, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
    const json = await res.json().catch(() => ({ ok: false, error: { code: 'bad_response', message: 'Phản hồi không phải JSON.' } }));
    if (!json.ok) { const e = new Error(json.error.message); Object.assign(e, json.error, { status: res.status }); throw e; }
    return json.meta ? Object.assign(json.data, { _meta: json.meta }) : json.data;
  }

  async login(identifier, password, client = this.token === null ? 'web' : 'app') {
    const d = await this.request('POST', '/auth/login/', { body: { identifier, password, client } });
    if (d.token) this.token = d.token; if (d.csrf_token) this.csrf = d.csrf_token;
    return d;
  }
  get(p, query) { return this.request('GET', p, { query }); }
  post(p, body = {}) { return this.request('POST', p, { body }); }
  patch(p, body) { return this.request('PATCH', p, { body }); }
  del(p) { return this.request('DELETE', p); }
}
// Ví dụ:  const api = new ManageApi(); await api.login('admin@x.com','***'); const users = await api.get('/users/', {q:'an', page:1});
