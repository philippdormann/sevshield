// Same-origin admin API. Auth is an httpOnly session cookie set by
// POST /admin/login; the token itself is never stored in the browser.
export async function adminFetch(path: string, init?: RequestInit) {
  const res = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) }
  });
  if (res.status === 401) throw new Error('unauthorized');
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? `request failed (${res.status})`);
  return body;
}
