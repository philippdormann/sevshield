<script lang="ts">
  import { onMount } from 'svelte';
  import {
    Activity,
    Ban,
    Pencil,
    Plus,
    Power,
    PowerOff,
    RefreshCw,
    RotateCw,
    Search,
    Trash2,
    X
  } from 'lucide-svelte';
  import * as Sidebar from '#components/ui/sidebar/index.js';
  import * as Breadcrumb from '#components/ui/breadcrumb/index.js';
  import { Separator } from '#components/ui/separator/index.js';
  import { Button } from '#components/ui/button/index.js';
  import { Badge } from '#components/ui/badge/index.js';
  import * as Card from '#components/ui/card/index.js';
  import { Input } from '#components/ui/input/index.js';
  import { Label } from '#components/ui/label/index.js';
  import * as Select from '#components/ui/select/index.js';
  import { Checkbox } from '#components/ui/checkbox/index.js';
  import * as Dialog from '#components/ui/dialog/index.js';
  import * as Table from '#components/ui/table/index.js';
  import AppSidebar from '#lib/components/app-sidebar.svelte';
  import ConfirmCode from '#lib/components/confirm-code.svelte';
  import StatCards from '#lib/components/stat-cards.svelte';
  import { adminFetch } from '#lib/api';

  type Tab = 'keys' | 'upstreams' | 'notify' | 'audit';

  const TITLES: Record<Tab, { title: string; hint: string }> = {
    keys: { title: 'Sub-keys', hint: 'Least-privilege keys bound to one god key and policy.' },
    upstreams: { title: 'God keys', hint: 'Full-access sevDesk tokens, encrypted at rest.' },
    notify: { title: 'Notifications', hint: 'Webhook, SMTP and Telegram alerts for denied calls and upstream errors.' },
    audit: { title: 'Audit logs', hint: 'Every proxied call and every admin action.' }
  };

  let token = $state('');
  let authed = $state(false);
  let loginError = $state<string | null>(null);
  let loggingIn = $state(false);
  let tab = $state<Tab>('keys');

  let keys = $state<any[]>([]);
  let upstreams = $state<any[]>([]);
  let policies = $state<any[]>([]);
  let channels = $state<any[]>([]);
  let audit = $state<any[]>([]);
  let auditTotal = $state(0);

  let loading = $state(false);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let stats = $state<any | null>(null);

  const keyStats = $derived.by(() => {
    const total = keys.length;
    const active = keys.filter((k: any) => k.active).length;
    const week = Date.now() + 7 * 24 * 3600 * 1000;
    const expiring = keys.filter(
      (k: any) => k.active && k.expiresAt && new Date(k.expiresAt).getTime() < week
    ).length;
    return [
      { label: 'Sub-keys', value: stats?.keys.total ?? total, sub: 'total issued' },
      { label: 'Active', value: stats?.keys.active ?? active, sub: 'can authenticate' },
      { label: 'Revoked', value: (stats?.keys.total ?? total) - (stats?.keys.active ?? active), sub: 'blocked keys' },
      { label: 'Expiring ≤ 7d', value: expiring, sub: 'needs attention' }
    ];
  });

  const upstreamStats = $derived.by(() => {
    const bound = upstreams.reduce((n: number, u: any) => n + (u.keys ?? 0), 0);
    const disabled = upstreams.filter((u: any) => !u.active).length;
    return [
      { label: 'God keys', value: stats?.upstreams.total ?? upstreams.length, sub: 'connected accounts' },
      { label: 'Active', value: stats?.upstreams.active ?? upstreams.length - disabled, sub: 'forwarding traffic' },
      { label: 'Disabled', value: disabled, sub: 'returning 503' },
      { label: 'Sub-keys bound', value: bound, sub: 'across all accounts' }
    ];
  });

  const channelStats = $derived.by(() => {
    const types = new Set(channels.map((c: any) => c.type)).size;
    const muted = channels.filter((c: any) => !c.active).length;
    return [
      { label: 'Channels', value: stats?.channels.total ?? channels.length, sub: 'webhook · telegram · smtp' },
      { label: 'Active', value: stats?.channels.active ?? channels.length - muted, sub: 'receiving alerts' },
      { label: 'Muted', value: muted, sub: 'paused channels' },
      { label: 'Event types', value: types, sub: 'channel kinds in use' }
    ];
  });

  const auditStats = $derived([
    { label: 'Total events', value: stats?.audit.total ?? auditTotal, sub: 'all time' },
    { label: 'Denied · 24h', value: stats?.audit.denied24h ?? '—', sub: '401 / 403 responses' },
    { label: 'Upstream errors · 24h', value: stats?.audit.upstreamErrors24h ?? '—', sub: 'bad gateway + 5xx' }
  ]);

  function flash(msg: string) {
    notice = msg;
    setTimeout(() => (notice = null), 4000);
  }

  // sub-key filters (client-side)
  let kSearch = $state('');
  let kUpstream = $state('all');
  let kStatus = $state('all');

  const filteredKeys = $derived.by(() => {
    const q = kSearch.trim().toLowerCase();
    return keys.filter((k: any) => {
      if (kUpstream !== 'all' && k.upstreamId !== kUpstream && k.upstream !== kUpstream) return false;
      if (kStatus === 'active' && !k.active) return false;
      if (kStatus === 'revoked' && k.active) return false;
      if (q && !(k.name.toLowerCase().includes(q) || (k.prefix ?? '').toLowerCase().includes(q))) return false;
      return true;
    });
  });

  function clearKeyFilters() {
    kSearch = '';
    kUpstream = 'all';
    kStatus = 'all';
  }

  const keyFiltersActive = $derived(kSearch.trim() !== '' || kUpstream !== 'all' || kStatus !== 'all');

  // sub-key creation (policy fixed to default; change later via edit)
  let showCreateKey = $state(false);
  let newKeyName = $state('');
  let newKeyUpstream = $state('');
  let newKeyIPs = $state('');
  let newKeyExpiry = $state('');
  let createdKey = $state<string | null>(null);

  // sub-key editing (permissions editable at any time)
  let showEditKey = $state(false);
  let editKey = $state<any | null>(null);
  let editName = $state('');
  let editPolicy = $state('');
  let editIPs = $state('');
  let editExpiry = $state('');

  // rotation result (shown once)
  let showRotated = $state(false);
  let rotated = $state<{ name: string; key: string } | null>(null);

  // god key creation / rotation
  let showCreateUpstream = $state(false);
  let newUpName = $state('');
  let newUpGod = $state('');
  let showRotateUp = $state(false);
  let rotateUp = $state<any | null>(null);
  let rotateGod = $state('');
  let testResult = $state<Record<string, string>>({});

  // notifications
  let showCreateChannel = $state(false);
  let newChName = $state('');
  let newChType = $state('webhook');
  let newChDenied = $state(true);
  let newChUpstreamErr = $state(true);
  let newChCooldown = $state(300);
  let newChUrl = $state('');
  let newChSecret = $state('');
  let newChBotToken = $state('');
  let newChChatId = $state('');
  let newChHost = $state('');
  let newChPort = $state('587');
  let newChUser = $state('');
  let newChPass = $state('');
  let newChFrom = $state('');
  let newChTo = $state('');
  let chTestResult = $state<Record<string, string>>({});

  // audit filters
  let fSource = $state('');
  let fUpstream = $state('');
  let fPrefix = $state('');
  let fStatus = $state('');
  let fLimit = $state(100);
  let fOffset = $state(0);
  let autoRefresh = $state(false);

  // audit retention (0 = unlimited, the default)
  let retentionDays = $state(0);
  let retentionMsg = $state<string | null>(null);

  // destructive confirmations (6-digit code dialog)
  let confirmOpen = $state(false);
  let pending = $state<{
    title: string;
    description: string;
    confirmLabel: string;
    run: () => Promise<void>;
  } | null>(null);

  function askConfirm(p: typeof pending) {
    pending = p;
    confirmOpen = true;
  }

  async function login() {
    loginError = null;
    loggingIn = true;
    try {
      await adminFetch('/admin/login', { method: 'POST', body: JSON.stringify({ token }) });
      authed = true;
      token = '';
      await loadAll();
    } catch {
      loginError = 'Invalid admin token.';
    } finally {
      loggingIn = false;
    }
  }

  async function logout() {
    try {
      await adminFetch('/admin/logout', { method: 'POST' });
    } catch {
      /* already logged out */
    }
    authed = false;
    keys = [];
    upstreams = [];
    channels = [];
    audit = [];
    stats = null;
  }

  async function loadAll() {
    loading = true;
    error = null;
    try {
      const [k, u, p, n, s] = await Promise.all([
        adminFetch('/admin/keys'),
        adminFetch('/admin/upstreams'),
        adminFetch('/admin/policies'),
        adminFetch('/admin/notify'),
        adminFetch('/admin/stats')
      ]);
      keys = k;
      upstreams = u;
      policies = p;
      channels = n;
      stats = s;
      try {
        const st = await adminFetch('/admin/settings');
        retentionDays = st.auditRetentionDays ?? 0;
      } catch {
        retentionDays = 0;
      }
      if (!newKeyUpstream && u[0]) newKeyUpstream = u[0].name;
      await loadAudit();
    } catch (e: any) {
      if (String(e.message).includes('unauthorized')) return logout();
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function loadAudit() {
    const q = new URLSearchParams({ limit: String(fLimit), offset: String(fOffset) });
    if (fSource) q.set('source', fSource);
    if (fUpstream) q.set('upstream', fUpstream);
    if (fPrefix.trim()) q.set('keyPrefix', fPrefix.trim());
    if (fStatus) q.set('status', fStatus);
    try {
      const d = await adminFetch(`/admin/audit?${q}`);
      audit = d.rows ?? [];
      auditTotal = d.total ?? 0;
    } catch (e: any) {
      if (String(e.message).includes('unauthorized')) return logout();
      error = e.message;
    }
  }

  function resetAuditPage() {
    fOffset = 0;
    loadAudit();
  }

  async function saveRetention() {
    error = null;
    retentionMsg = null;
    try {
      const days = Math.max(0, Math.min(3650, Math.floor(Number(retentionDays) || 0)));
      const r = await adminFetch('/admin/settings', {
        method: 'PUT',
        body: JSON.stringify({ auditRetentionDays: days })
      });
      retentionDays = r.auditRetentionDays ?? days;
      retentionMsg =
        retentionDays === 0
          ? 'Retention set to unlimited — audit logs are kept forever.'
          : `Retention set to ${retentionDays} days — ${r.purged ?? 0} old rows deleted.`;
      await loadAudit();
      const s = await adminFetch('/admin/stats');
      stats = s;
    } catch (e: any) {
      error = e.message;
    }
  }

  async function purgeAuditNow() {
    error = null;
    retentionMsg = null;
    try {
      const r = await adminFetch('/admin/audit/purge', { method: 'POST', body: JSON.stringify({}) });
      retentionMsg = `Purged ${r.deleted ?? 0} rows older than ${r.retentionDays} days.`;
      await loadAudit();
      const s = await adminFetch('/admin/stats');
      stats = s;
    } catch (e: any) {
      error = e.message;
    }
  }

  function defaultPolicyName() {
    return policies.find((p: any) => p.name === 'sevdesk-sync')?.name ?? policies[0]?.name ?? '';
  }

  async function createKey() {
    error = null;
    createdKey = null;
    try {
      const res = await adminFetch('/admin/keys', {
        method: 'POST',
        body: JSON.stringify({
          name: newKeyName,
          policy: defaultPolicyName(),
          upstream: newKeyUpstream,
          allowedIPs: newKeyIPs,
          expiresAt: newKeyExpiry ? new Date(newKeyExpiry).toISOString() : null
        })
      });
      createdKey = res.key;
      newKeyName = '';
      newKeyExpiry = '';
      newKeyIPs = '';
      await loadAll();
    } catch (e: any) {
      error = e.message;
    }
  }

  function startEditKey(k: any) {
    editKey = k;
    showEditKey = true;
    editName = k.name;
    editPolicy = k.policy;
    editIPs = k.allowedIPs ?? '';
    editExpiry = k.expiresAt ? k.expiresAt.slice(0, 16) : '';
  }

  async function saveKey() {
    if (!editKey) return;
    error = null;
    try {
      await adminFetch(`/admin/keys/${editKey.id}`, {
        method: 'PUT',
        body: JSON.stringify({
          name: editName,
          policy: editPolicy,
          allowedIPs: editIPs,
          expiresAt: editExpiry ? new Date(editExpiry).toISOString() : null
        })
      });
      editKey = null;
      showEditKey = false;
      flash('Sub-key updated.');
      await loadAll();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function rotateKey(id: string) {
    error = null;
    try {
      const res = await adminFetch(`/admin/keys/${id}/rotate`, { method: 'POST' });
      const k = keys.find((x) => x.id === id);
      rotated = { name: k?.name ?? 'sub-key', key: res.key };
      showRotated = true;
      await loadAll();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function revokeKey(id: string) {
    await adminFetch(`/admin/keys/${id}/revoke`, { method: 'POST' });
    flash('Sub-key revoked.');
    await loadAll();
  }

  async function deleteKey(id: string) {
    await adminFetch(`/admin/keys/${id}`, { method: 'DELETE' });
    flash('Sub-key deleted.');
    await loadAll();
  }

  async function createUpstream() {
    error = null;
    try {
      await adminFetch('/admin/upstreams', {
        method: 'POST',
        body: JSON.stringify({ name: newUpName, godKey: newUpGod })
      });
      newUpName = '';
      newUpGod = '';
      showCreateUpstream = false;
      flash('God key added.');
      await loadAll();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function toggleUpstream(u: any) {
    await adminFetch(`/admin/upstreams/${u.id}`, {
      method: 'PUT',
      body: JSON.stringify({ active: !u.active })
    });
    await loadAll();
  }

  async function rotateUpstream() {
    if (!rotateUp) return;
    error = null;
    try {
      await adminFetch(`/admin/upstreams/${rotateUp.id}`, {
        method: 'PUT',
        body: JSON.stringify({ godKey: rotateGod })
      });
      rotateUp = null;
      showRotateUp = false;
      rotateGod = '';
      flash('God key rotated. Revoke the old token in sevDesk if it leaked.');
      await loadAll();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function deleteUpstream(id: string) {
    try {
      await adminFetch(`/admin/upstreams/${id}`, { method: 'DELETE' });
      flash('Upstream deleted.');
      await loadAll();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function testUpstream(id: string) {
    testResult[id] = 'testing…';
    try {
      const r = await adminFetch(`/admin/upstreams/${id}/test`, { method: 'POST' });
      testResult[id] = r.ok ? `ok (${r.status})` : `failed (${r.status ?? '?'})`;
    } catch (e: any) {
      testResult[id] = 'error: ' + e.message;
    }
  }

  async function createChannel() {
    error = null;
    try {
      const events = [...(newChDenied ? ['denied'] : []), ...(newChUpstreamErr ? ['upstream_error'] : [])];
      const config =
        newChType === 'webhook'
          ? { url: newChUrl, secret: newChSecret || undefined }
          : newChType === 'telegram'
            ? { botToken: newChBotToken, chatId: newChChatId }
            : {
                host: newChHost,
                port: newChPort ? parseInt(newChPort, 10) : 587,
                username: newChUser || undefined,
                password: newChPass || undefined,
                from: newChFrom,
                to: newChTo
              };
      await adminFetch('/admin/notify', {
        method: 'POST',
        body: JSON.stringify({ name: newChName, type: newChType, events, cooldownSeconds: newChCooldown, config })
      });
      newChName = '';
      newChUrl = '';
      newChSecret = '';
      newChBotToken = '';
      newChChatId = '';
      newChHost = '';
      newChUser = '';
      newChPass = '';
      newChFrom = '';
      newChTo = '';
      showCreateChannel = false;
      flash('Notification channel added.');
      await loadAll();
    } catch (e: any) {
      error = e.message;
    }
  }

  async function toggleChannel(ch: any) {
    await adminFetch(`/admin/notify/${ch.id}`, {
      method: 'PUT',
      body: JSON.stringify({ active: !ch.active })
    });
    await loadAll();
  }

  async function deleteChannel(id: string) {
    await adminFetch(`/admin/notify/${id}`, { method: 'DELETE' });
    flash('Channel deleted.');
    await loadAll();
  }

  async function testChannel(id: string) {
    chTestResult[id] = 'sending…';
    try {
      const r = await adminFetch(`/admin/notify/${id}/test`, { method: 'POST' });
      chTestResult[id] = r.ok ? 'delivered' : 'failed: ' + (r.error ?? '?');
    } catch (e: any) {
      chTestResult[id] = 'error: ' + e.message;
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      flash('Copied to clipboard.');
    } catch {
      error = 'Copy failed - select the text manually.';
    }
  }

  function statusClass(s: number) {
    if (s < 400) return 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300';
    if (s < 500) return 'bg-amber-500/10 text-amber-700 dark:text-amber-300';
    return 'bg-red-500/10 text-red-700 dark:text-red-300';
  }

  function fmtTime(iso: string) {
    return new Date(iso).toLocaleString();
  }

  function upstreamName(id: string) {
    return upstreams.find((x) => x.id === id)?.name ?? 'unknown';
  }

  onMount(async () => {
    try {
      await adminFetch('/admin/me');
      authed = true;
      await loadAll();
    } catch {
      authed = false;
    }
  });

  $effect(() => {
    if (!autoRefresh || !authed || tab !== 'audit') return;
    const t = setInterval(loadAudit, 10000);
    return () => clearInterval(t);
  });
</script>

{#if !authed}
  <div class="flex min-h-svh items-center justify-center p-4">
    <Card.Root class="w-full max-w-sm">
      <Card.Header>
        <Card.Title class="text-2xl">sevshield</Card.Title>
        <Card.Description>Scoped sevDesk API keys with audit logging.</Card.Description>
      </Card.Header>
      <Card.Content class="space-y-4">
        <div class="space-y-2">
          <Label for="admin-token">Admin token</Label>
          <Input
            id="admin-token"
            type="password"
            bind:value={token}
            onkeydown={(e) => e.key === 'Enter' && login()}
            placeholder="ADMIN_TOKEN"
            autocomplete="current-password"
            class="font-mono"
          />
        </div>
        {#if loginError}<p class="text-sm text-red-600 dark:text-red-400">{loginError}</p>{/if}
        <Button onclick={login} disabled={loggingIn || !token} class="w-full">
          {loggingIn ? 'Connecting…' : 'Sign in'}
        </Button>
        <p class="text-xs leading-relaxed text-muted-foreground">
          Sign-in sets a session cookie (httpOnly). The token itself is never stored in this browser.
        </p>
      </Card.Content>
    </Card.Root>
  </div>
{:else}
  <Sidebar.Provider>
    <AppSidebar
      {tab}
      keyCount={keys.length}
      upstreamCount={upstreams.length}
      channelCount={channels.length}
      onselect={(t) => {
        tab = t;
        if (t === 'audit') loadAudit();
      }}
      onlogout={logout}
    />
    <Sidebar.Inset>
      <header class="flex h-16 shrink-0 items-center gap-2 border-b px-4">
        <Sidebar.Trigger />
        <Separator orientation="vertical" class="h-4" />
        <Breadcrumb.Root>
          <Breadcrumb.List>
            <Breadcrumb.Item>
              <Breadcrumb.Link href="/">sevshield</Breadcrumb.Link>
            </Breadcrumb.Item>
            <Breadcrumb.Separator />
            <Breadcrumb.Item>
              <Breadcrumb.Page>{TITLES[tab].title}</Breadcrumb.Page>
            </Breadcrumb.Item>
          </Breadcrumb.List>
        </Breadcrumb.Root>
        <div class="ml-auto flex items-center gap-2">
          <Button variant="outline" size="sm" onclick={loadAll} disabled={loading}>
            <RefreshCw />
            {loading ? 'Loading…' : 'Refresh'}
          </Button>
        </div>
      </header>

      <main class="flex flex-1 flex-col gap-4 p-4 lg:gap-6 lg:p-6">
        <div>
          <h1 class="text-lg font-semibold tracking-tight">{TITLES[tab].title}</h1>
          <p class="text-sm text-muted-foreground">{TITLES[tab].hint}</p>
        </div>
        {#if error}
          <p class="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
            {error}
          </p>
        {/if}
        {#if notice}
          <p class="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-300">
            {notice}
          </p>
        {/if}

        {#if tab === 'keys'}
          <StatCards stats={keyStats} />

          <Card.Root>
            <Card.Header>
              <Card.Title>Sub-keys</Card.Title>
              <Card.Description>Least-privilege keys bound to one god key and policy.</Card.Description>
              <Card.Action>
                <Button size="sm" onclick={() => { createdKey = null; showCreateKey = true; }}>
                  <Plus /> New sub-key
                </Button>
              </Card.Action>
            </Card.Header>
            <Card.Content class="px-2 sm:px-3">
            <div class="flex flex-wrap items-center gap-2 px-2 pb-4 pt-1 sm:px-3">
              <div class="relative w-full sm:max-w-xs">
                <Search class="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input bind:value={kSearch} placeholder="Search name or prefix…" class="pl-9" />
              </div>
              <Select.Root type="single" bind:value={kUpstream}>
                <Select.Trigger class="w-full sm:w-44"><Select.Value placeholder="All god keys" /></Select.Trigger>
                <Select.Content>
                  <Select.Item value="all" label="All god keys">All god keys</Select.Item>
                  {#each upstreams as u (u.id)}
                    <Select.Item value={u.id} label={u.name}>{u.name}</Select.Item>
                  {/each}
                </Select.Content>
              </Select.Root>
              <Select.Root type="single" bind:value={kStatus}>
                <Select.Trigger class="w-full sm:w-36"><Select.Value placeholder="Any status" /></Select.Trigger>
                <Select.Content>
                  <Select.Item value="all" label="Any status">Any status</Select.Item>
                  <Select.Item value="active" label="Active">Active</Select.Item>
                  <Select.Item value="revoked" label="Revoked">Revoked</Select.Item>
                </Select.Content>
              </Select.Root>
              {#if keyFiltersActive}
                <Button variant="ghost" size="sm" onclick={clearKeyFilters}>
                  <X /> Clear
                </Button>
              {/if}
              <span class="ml-auto text-xs text-muted-foreground">
                {filteredKeys.length} of {keys.length}
              </span>
            </div>
            <Table.Root>
              <Table.Header>
                <Table.Row>
                  <Table.Head>Name</Table.Head>
                  <Table.Head>God key</Table.Head>
                  <Table.Head>Policy</Table.Head>
                  <Table.Head>Restrictions</Table.Head>
                  <Table.Head>Status</Table.Head>
                  <Table.Head class="text-right">Actions</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#if filteredKeys.length === 0}
                  <Table.Row>
                    <Table.Cell colspan={6} class="py-8 text-center text-muted-foreground">
                      {keys.length === 0 ? 'No sub-keys yet.' : 'No sub-keys match the current filters.'}
                    </Table.Cell>
                  </Table.Row>
                {:else}
                  {#each filteredKeys as k (k.id)}
                    <Table.Row>
                      <Table.Cell>
                        <div class="font-medium">{k.name}</div>
                        <div class="font-mono text-xs text-muted-foreground">{k.prefix}…</div>
                      </Table.Cell>
                      <Table.Cell>{k.upstream || '—'}</Table.Cell>
                      <Table.Cell><Badge variant="secondary">{k.policy || '—'}</Badge></Table.Cell>
                      <Table.Cell class="max-w-48">
                        <div class="truncate font-mono text-xs text-muted-foreground" title={k.allowedIPs}>
                          {k.allowedIPs || 'any IP'}
                        </div>
                        <div class="text-xs text-muted-foreground">
                          {#if k.lastUsedAt}used {fmtTime(k.lastUsedAt)}{/if}
                          {#if k.expiresAt} · expires {fmtTime(k.expiresAt)}{/if}
                        </div>
                      </Table.Cell>
                      <Table.Cell>
                        <Badge variant={k.active ? 'default' : 'outline'}>
                          {k.active ? 'active' : 'revoked'}
                        </Badge>
                      </Table.Cell>
                      <Table.Cell>
                        <div class="flex justify-end gap-1">
                          <Button variant="ghost" size="icon-sm" title="Edit name, policy, IPs, expiry" onclick={() => startEditKey(k)}>
                            <Pencil />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            title="Rotate: issue fresh key material"
                            onclick={() =>
                              askConfirm({
                                title: 'Rotate sub-key?',
                                description: `"${k.name}" gets a new secret. The old one stops working immediately.`,
                                confirmLabel: 'Rotate',
                                run: () => rotateKey(k.id)
                              })}
                          >
                            <RotateCw />
                          </Button>
                          {#if k.active}
                            <Button
                              variant="ghost"
                              size="icon-sm"
                              title="Revoke this sub-key"
                              onclick={() =>
                                askConfirm({
                                  title: 'Revoke sub-key?',
                                  description: `"${k.name}" stops working immediately. This can be undone only by issuing a new key.`,
                                  confirmLabel: 'Revoke',
                                  run: () => revokeKey(k.id)
                                })}
                            >
                              <Ban />
                            </Button>
                          {/if}
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            title="Delete this sub-key"
                            class="text-red-600 hover:text-red-600 dark:text-red-400"
                            onclick={() =>
                              askConfirm({
                                title: 'Delete sub-key?',
                                description: `"${k.name}" and its audit trail reference are removed. This cannot be undone.`,
                                confirmLabel: 'Delete',
                                run: () => deleteKey(k.id)
                              })}
                          >
                            <Trash2 />
                          </Button>
                        </div>
                      </Table.Cell>
                    </Table.Row>
                  {/each}
                {/if}
              </Table.Body>
            </Table.Root>
            </Card.Content>
          </Card.Root>
        {/if}

        {#if tab === 'upstreams'}
          <StatCards stats={upstreamStats} />

          <Card.Root>
            <Card.Header>
              <Card.Title>God keys</Card.Title>
              <Card.Description>Full-access sevDesk tokens, encrypted at rest. Never leaves the server.</Card.Description>
              <Card.Action>
                <Button size="sm" onclick={() => { showCreateUpstream = true; }}>
                  <Plus /> Add god key
                </Button>
              </Card.Action>
            </Card.Header>
            <Card.Content class="px-2 sm:px-3">
            <Table.Root>
              <Table.Header>
                <Table.Row>
                  <Table.Head>Status</Table.Head>
                  <Table.Head>Name</Table.Head>
                  <Table.Head class="text-right">Actions</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#if upstreams.length === 0}
                  <Table.Row>
                    <Table.Cell colspan={3} class="text-center text-muted-foreground">
                      No god keys configured.
                    </Table.Cell>
                  </Table.Row>
                {:else}
                  {#each upstreams as u (u.id)}
                    <Table.Row>
                      <Table.Cell>
                        <Badge variant={u.active ? 'default' : 'outline'}>
                          {u.active ? 'active' : 'disabled'}
                        </Badge>
                      </Table.Cell>
                      <Table.Cell>
                        <div class="font-medium">{u.name}</div>
                        <div class="font-mono text-xs text-muted-foreground">
                          token {u.keyHint} · {u.keys} sub-keys
                        </div>
                        {#if testResult[u.id]}
                          <div class="font-mono text-xs text-muted-foreground">{testResult[u.id]}</div>
                        {/if}
                      </Table.Cell>
                      <Table.Cell>
                        <div class="flex justify-end gap-1">
                          <Button variant="ghost" size="icon-sm" title="Send a live read to sevDesk" onclick={() => testUpstream(u.id)}>
                            <Activity />
                          </Button>
                          {#if u.active}
                            <Button variant="ghost" size="icon-sm" title="Disable: bound sub-keys get 503" onclick={() => toggleUpstream(u)}>
                              <PowerOff />
                            </Button>
                          {:else}
                            <Button variant="ghost" size="icon-sm" title="Re-enable this god key" onclick={() => toggleUpstream(u)}>
                              <Power />
                            </Button>
                          {/if}
                          <Button variant="ghost" size="icon-sm" title="Replace the stored god key" onclick={() => { rotateUp = u; rotateGod = ''; showRotateUp = true; }}>
                            <RefreshCw />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            title="Delete (blocked while sub-keys exist)"
                            class="text-red-600 hover:text-red-600 dark:text-red-400"
                            onclick={() =>
                              askConfirm({
                                title: 'Delete god key?',
                                description: `"${u.name}" is removed. Blocked while sub-keys are bound to it.`,
                                confirmLabel: 'Delete',
                                run: () => deleteUpstream(u.id)
                              })}
                          >
                            <Trash2 />
                          </Button>
                        </div>
                      </Table.Cell>
                    </Table.Row>
                  {/each}
                {/if}
              </Table.Body>
            </Table.Root>
            </Card.Content>
          </Card.Root>
        {/if}

        {#if tab === 'notify'}
          <StatCards stats={channelStats} />

          <Card.Root>
            <Card.Header>
              <Card.Title>Notifications</Card.Title>
              <Card.Description>Alerts for denied calls and upstream errors, per channel with cooldown.</Card.Description>
              <Card.Action>
                <Button size="sm" onclick={() => (showCreateChannel = true)}>
                  <Plus /> Add channel
                </Button>
              </Card.Action>
            </Card.Header>
            <Card.Content class="px-2 sm:px-3">
            <Table.Root>
              <Table.Header>
                <Table.Row>
                  <Table.Head>Status</Table.Head>
                  <Table.Head>Channel</Table.Head>
                  <Table.Head class="text-right">Actions</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#if channels.length === 0}
                  <Table.Row>
                    <Table.Cell colspan={3} class="text-center text-muted-foreground">
                      No notification channels yet.
                    </Table.Cell>
                  </Table.Row>
                {:else}
                  {#each channels as ch (ch.id)}
                    <Table.Row>
                      <Table.Cell>
                        <Badge variant={ch.active ? 'default' : 'outline'}>
                          {ch.active ? 'active' : 'muted'}
                        </Badge>
                      </Table.Cell>
                      <Table.Cell>
                        <div class="font-medium">{ch.name} <span class="font-mono text-xs text-muted-foreground">{ch.type}</span></div>
                        <div class="truncate font-mono text-xs text-muted-foreground">
                          {ch.target} · {ch.events.join(', ')} · cooldown {ch.cooldownSeconds}s
                        </div>
                        {#if chTestResult[ch.id]}
                          <div class="font-mono text-xs text-muted-foreground">{chTestResult[ch.id]}</div>
                        {/if}
                      </Table.Cell>
                      <Table.Cell>
                        <div class="flex justify-end gap-1">
                          <Button variant="ghost" size="icon-sm" title="Send test alert" onclick={() => testChannel(ch.id)}>
                            <Activity />
                          </Button>
                          <Button variant="ghost" size="icon-sm" title={ch.active ? 'Mute' : 'Unmute'} onclick={() => toggleChannel(ch)}>
                            {#if ch.active}<PowerOff />{:else}<Power />{/if}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            title="Delete channel"
                            class="text-red-600 hover:text-red-600 dark:text-red-400"
                            onclick={() =>
                              askConfirm({
                                title: 'Delete channel?',
                                description: `"${ch.name}" stops receiving alerts.`,
                                confirmLabel: 'Delete',
                                run: () => deleteChannel(ch.id)
                              })}
                          >
                            <Trash2 />
                          </Button>
                        </div>
                      </Table.Cell>
                    </Table.Row>
                  {/each}
                {/if}
              </Table.Body>
            </Table.Root>
            </Card.Content>
          </Card.Root>
        {/if}

        {#if tab === 'audit'}
          <StatCards stats={auditStats} />

          <Card.Root>
            <Card.Header>
              <Card.Title>Retention</Card.Title>
              <Card.Description>
                Rows older than N days are deleted on save, on startup and daily. 0 keeps everything (default).
              </Card.Description>
            </Card.Header>
            <Card.Content>
              <div class="flex flex-wrap items-end gap-4">
                <div class="space-y-2">
                  <Label for="ret-days">Keep audit logs (days, 0 = unlimited)</Label>
                  <Input id="ret-days" type="number" min={0} max={3650} bind:value={retentionDays} class="w-40 font-mono" />
                </div>
                <Button size="sm" onclick={saveRetention}>Save</Button>
                <Button
                  variant="outline"
                  size="sm"
                  onclick={() =>
                    askConfirm({
                      title: 'Purge old audit logs?',
                      description: 'Deletes audit rows older than the configured retention. This cannot be undone.',
                      confirmLabel: 'Purge',
                      run: purgeAuditNow
                    })}
                >
                  Purge now
                </Button>
              </div>
              {#if retentionMsg}<p class="pt-3 text-xs text-muted-foreground">{retentionMsg}</p>{/if}
            </Card.Content>
          </Card.Root>

          <Card.Root>
            <Card.Header>
              <Card.Title>Filters</Card.Title>
              <Card.Description>Narrow the audit trail by source, account, key or status.</Card.Description>
            </Card.Header>
            <Card.Content>
              <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
                <div class="space-y-2">
                  <Label>Source</Label>
                  <Select.Root type="single" bind:value={fSource} onValueChange={resetAuditPage}>
                    <Select.Trigger class="w-full"><Select.Value placeholder="proxy + admin" /></Select.Trigger>
                    <Select.Content>
                      <Select.Item value="" label="proxy + admin">proxy + admin</Select.Item>
                      <Select.Item value="proxy" label="proxy">proxy</Select.Item>
                      <Select.Item value="admin" label="admin">admin</Select.Item>
                    </Select.Content>
                  </Select.Root>
                </div>
                <div class="space-y-2">
                  <Label>God key</Label>
                  <Select.Root type="single" bind:value={fUpstream} onValueChange={resetAuditPage}>
                    <Select.Trigger class="w-full"><Select.Value placeholder="all god keys" /></Select.Trigger>
                    <Select.Content>
                      <Select.Item value="" label="all god keys">all god keys</Select.Item>
                      {#each upstreams as u (u.id)}
                        <Select.Item value={u.id} label={u.name}>{u.name}</Select.Item>
                      {/each}
                    </Select.Content>
                  </Select.Root>
                </div>
                <div class="space-y-2">
                  <Label for="af-prefix">Sub-key prefix</Label>
                  <Input id="af-prefix" bind:value={fPrefix} onchange={resetAuditPage} placeholder="e.g. sevsh_4f2a" class="font-mono" />
                </div>
                <div class="space-y-2">
                  <Label for="af-status">Status</Label>
                  <Input id="af-status" bind:value={fStatus} onchange={resetAuditPage} placeholder="e.g. 403" inputmode="numeric" class="font-mono" />
                </div>
                <div class="space-y-2">
                  <Label>Page size</Label>
                  <Select.Root type="single" value={String(fLimit)} onValueChange={(v) => { fLimit = Number(v); resetAuditPage(); }}>
                    <Select.Trigger class="w-full"><Select.Value placeholder="100" /></Select.Trigger>
                    <Select.Content>
                      <Select.Item value="50" label="50">50</Select.Item>
                      <Select.Item value="100" label="100">100</Select.Item>
                      <Select.Item value="200" label="200">200</Select.Item>
                    </Select.Content>
                  </Select.Root>
                </div>
              </div>
            </Card.Content>
            <Card.Footer class="flex flex-wrap items-center gap-2">
              <Button size="sm" onclick={loadAudit}>Apply filters</Button>
              {#if fSource || fUpstream || fPrefix.trim() || fStatus}
                <Button
                  variant="ghost"
                  size="sm"
                  onclick={() => { fSource = ''; fUpstream = ''; fPrefix = ''; fStatus = ''; resetAuditPage(); }}
                >
                  <X /> Clear
                </Button>
              {/if}
              <label class="ml-auto flex items-center gap-1.5 text-xs text-muted-foreground">
                <Checkbox bind:checked={autoRefresh} /> auto-refresh
              </label>
              <span class="text-xs text-muted-foreground tabular-nums">{auditTotal} entries</span>
            </Card.Footer>
          </Card.Root>

          <Card.Root>
            <Card.Header>
              <Card.Title>Events</Card.Title>
              <Card.Description>Newest first. Admin calls and proxied API calls.</Card.Description>
            </Card.Header>
            <Card.Content class="px-2 sm:px-3">
            <Table.Root>
              <Table.Header>
                <Table.Row>
                  <Table.Head class="w-20">Status</Table.Head>
                  <Table.Head class="w-24">Source</Table.Head>
                  <Table.Head>Request</Table.Head>
                  <Table.Head class="text-right">Duration</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {#if audit.length === 0}
                  <Table.Row>
                    <Table.Cell colspan={4} class="text-center text-muted-foreground">
                      No audit entries match.
                    </Table.Cell>
                  </Table.Row>
                {:else}
                  {#each audit as a (a.ID)}
                    {@const src = a.Source || 'proxy'}
                    <Table.Row>
                      <Table.Cell>
                        <span class="rounded px-1.5 py-0.5 font-mono text-xs font-semibold {statusClass(a.Status)}">{a.Status}</span>
                      </Table.Cell>
                      <Table.Cell><Badge variant="outline">{src}</Badge></Table.Cell>
                      <Table.Cell>
                        <div class="font-mono text-xs">
                          <span class="text-foreground">{a.Method}</span>
                          <span class="text-muted-foreground"> {a.Path}</span>
                        </div>
                        <div class="font-mono text-xs text-muted-foreground">
                          {fmtTime(a.CreatedAt)} ·
                          {#if src === 'admin'}
                            actor {a.Actor}
                          {:else}
                            {a.KeyPrefix}… · {a.UpstreamID ? upstreamName(a.UpstreamID) : 'no upstream'}
                          {/if}
                          · {a.ClientIP}
                          {#if a.Error}<span class="text-red-600 dark:text-red-400"> · {a.Error}</span>{/if}
                        </div>
                      </Table.Cell>
                      <Table.Cell class="text-right font-mono text-xs text-muted-foreground">{a.DurationMs}ms</Table.Cell>
                    </Table.Row>
                  {/each}
                {/if}
              </Table.Body>
            </Table.Root>
            </Card.Content>
            <Card.Footer class="flex items-center justify-between">
              <Button variant="outline" size="sm" onclick={() => { fOffset = Math.max(0, fOffset - fLimit); loadAudit(); }} disabled={fOffset === 0}>
                ← Newer
              </Button>
              <span class="text-xs text-muted-foreground">{fOffset + 1}–{Math.min(fOffset + fLimit, auditTotal)} of {auditTotal}</span>
              <Button variant="outline" size="sm" onclick={() => { fOffset += fLimit; loadAudit(); }} disabled={fOffset + fLimit >= auditTotal}>
                Older →
              </Button>
            </Card.Footer>
          </Card.Root>
        {/if}
      </main>
    </Sidebar.Inset>
  </Sidebar.Provider>
{/if}

<!-- create sub-key dialog -->
<Dialog.Root bind:open={showCreateKey}>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>New sub-key</Dialog.Title>
      <Dialog.Description>Bound to one god key with the default policy. Change the policy anytime via edit.</Dialog.Description>
    </Dialog.Header>
    <div class="space-y-4">
      <div class="space-y-2">
        <Label for="ck-name">Name</Label>
        <Input id="ck-name" bind:value={newKeyName} placeholder="e.g. shop-sync" />
      </div>
      <div class="space-y-2">
        <Label>God key</Label>
        <Select.Root type="single" bind:value={newKeyUpstream}>
          <Select.Trigger class="w-full"><Select.Value placeholder="Select god key" /></Select.Trigger>
          <Select.Content>
            {#each upstreams as u (u.id)}
              <Select.Item value={u.name} label={u.name}>{u.name}</Select.Item>
            {/each}
          </Select.Content>
        </Select.Root>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <div class="space-y-2">
          <Label for="ck-ips">Allowed IPs</Label>
          <Input id="ck-ips" bind:value={newKeyIPs} placeholder="empty = any" class="font-mono" />
        </div>
        <div class="space-y-2">
          <Label for="ck-exp">Expiry</Label>
          <Input id="ck-exp" type="datetime-local" bind:value={newKeyExpiry} />
        </div>
      </div>
      {#if createdKey}
        <div class="flex items-center gap-2 rounded-lg bg-muted p-3">
          <code class="flex-1 break-all font-mono text-sm">{createdKey}</code>
          <Button variant="outline" size="sm" onclick={() => createdKey && copy(createdKey)}>Copy</Button>
        </div>
        <p class="text-xs text-muted-foreground">Shown once. Send as <span class="font-mono">Authorization</span> header to <span class="font-mono">/api/v1/*</span>.</p>
      {/if}
    </div>
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (showCreateKey = false)}>Close</Button>
      <Button onclick={createKey} disabled={!newKeyName || !newKeyUpstream}>Create</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<!-- edit sub-key dialog -->
<Dialog.Root
  bind:open={showEditKey}
  onOpenChange={(o) => {
    showEditKey = o;
    if (!o) editKey = null;
  }}
>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>Edit sub-key</Dialog.Title>
      <Dialog.Description>Name, policy, IP allowlist and expiry can be changed at any time.</Dialog.Description>
    </Dialog.Header>
    {#if editKey}
      <div class="space-y-4">
        <div class="space-y-2">
          <Label for="ek-name">Name</Label>
          <Input id="ek-name" bind:value={editName} />
        </div>
        <div class="space-y-2">
          <Label>Policy</Label>
          <Select.Root type="single" bind:value={editPolicy}>
            <Select.Trigger class="w-full"><Select.Value placeholder="Select policy" /></Select.Trigger>
            <Select.Content>
              {#each policies as p (p.name)}
                <Select.Item value={p.name} label={`${p.name} (${p.rules.length} rules)`}>
                  {p.name} ({p.rules.length} rules)
                </Select.Item>
              {/each}
            </Select.Content>
          </Select.Root>
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div class="space-y-2">
            <Label for="ek-ips">Allowed IPs</Label>
            <Input id="ek-ips" bind:value={editIPs} placeholder="empty = any" class="font-mono" />
          </div>
          <div class="space-y-2">
            <Label for="ek-exp">Expiry</Label>
            <Input id="ek-exp" type="datetime-local" bind:value={editExpiry} />
          </div>
        </div>
      </div>
    {/if}
    <Dialog.Footer>
      <Button variant="outline" onclick={() => { showEditKey = false; editKey = null; }}>Cancel</Button>
      <Button onclick={saveKey}>Save</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<!-- rotated key result -->
<Dialog.Root
  bind:open={showRotated}
  onOpenChange={(o) => {
    showRotated = o;
    if (!o) rotated = null;
  }}
>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>Sub-key rotated</Dialog.Title>
      <Dialog.Description>
        New secret for "{rotated?.name}". Shown once — the old one stopped working immediately.
      </Dialog.Description>
    </Dialog.Header>
    {#if rotated}
      <div class="flex items-center gap-2 rounded-lg bg-muted p-3">
        <code class="flex-1 break-all font-mono text-sm">{rotated.key}</code>
        <Button variant="outline" size="sm" onclick={() => rotated && copy(rotated.key)}>Copy</Button>
      </div>
    {/if}
    <Dialog.Footer>
      <Button onclick={() => { showRotated = false; rotated = null; }}>Done</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<!-- create god key dialog -->
<Dialog.Root bind:open={showCreateUpstream}>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>Add god key</Dialog.Title>
      <Dialog.Description>One sevDesk account per god key. Stored AES-256-GCM encrypted, plaintext never shown again.</Dialog.Description>
    </Dialog.Header>
    <div class="space-y-4">
      <div class="space-y-2">
        <Label for="uk-name">Name</Label>
        <Input id="uk-name" bind:value={newUpName} placeholder="e.g. main-account" />
      </div>
      <div class="space-y-2">
        <Label for="uk-god">sevDesk API token</Label>
        <Input id="uk-god" type="password" bind:value={newUpGod} autocomplete="new-password" class="font-mono" />
      </div>
    </div>
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (showCreateUpstream = false)}>Cancel</Button>
      <Button onclick={createUpstream} disabled={!newUpName || !newUpGod}>Add</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<!-- rotate god key dialog -->
<Dialog.Root
  bind:open={showRotateUp}
  onOpenChange={(o) => {
    showRotateUp = o;
    if (!o) rotateUp = null;
  }}
>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>Rotate "{rotateUp?.name}"</Dialog.Title>
      <Dialog.Description>Replaces the stored token. Revoke the old token in sevDesk itself if it leaked.</Dialog.Description>
    </Dialog.Header>
    <div class="space-y-2">
      <Label for="uk-rot">New sevDesk API token</Label>
      <Input id="uk-rot" type="password" bind:value={rotateGod} autocomplete="new-password" class="font-mono" />
    </div>
    <Dialog.Footer>
      <Button variant="outline" onclick={() => { showRotateUp = false; rotateUp = null; }}>Cancel</Button>
      <Button onclick={rotateUpstream} disabled={!rotateGod}>Save</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<!-- create channel dialog -->
<Dialog.Root bind:open={showCreateChannel}>
  <Dialog.Content>
    <Dialog.Header>
      <Dialog.Title>Add notification channel</Dialog.Title>
      <Dialog.Description>Fires on denied calls and upstream errors.</Dialog.Description>
    </Dialog.Header>
    <div class="space-y-4">
      <div class="grid grid-cols-[1fr_140px_120px] gap-4">
        <div class="space-y-2">
          <Label for="nc-name">Name</Label>
          <Input id="nc-name" bind:value={newChName} placeholder="e.g. soc-webhook" />
        </div>
        <div class="space-y-2">
          <Label>Type</Label>
          <Select.Root type="single" bind:value={newChType}>
            <Select.Trigger class="w-full"><Select.Value placeholder="type" /></Select.Trigger>
            <Select.Content>
              <Select.Item value="webhook" label="webhook">webhook</Select.Item>
              <Select.Item value="telegram" label="telegram">telegram</Select.Item>
              <Select.Item value="smtp" label="smtp">smtp</Select.Item>
            </Select.Content>
          </Select.Root>
        </div>
        <div class="space-y-2">
          <Label for="nc-cd">Cooldown (s)</Label>
          <Input id="nc-cd" type="number" min={0} bind:value={newChCooldown} class="font-mono" />
        </div>
      </div>
      <div class="flex gap-4 text-sm">
        <label class="flex items-center gap-1.5"><Checkbox bind:checked={newChDenied} /> denied</label>
        <label class="flex items-center gap-1.5"><Checkbox bind:checked={newChUpstreamErr} /> upstream errors</label>
      </div>
      {#if newChType === 'webhook'}
        <div class="grid grid-cols-[2fr_1fr] gap-4">
          <div class="space-y-2">
            <Label for="nc-url">URL</Label>
            <Input id="nc-url" bind:value={newChUrl} placeholder="https://hooks.example.com/sevshield" class="font-mono" />
          </div>
          <div class="space-y-2">
            <Label for="nc-sec">HMAC secret</Label>
            <Input id="nc-sec" type="password" bind:value={newChSecret} autocomplete="new-password" class="font-mono" />
          </div>
        </div>
      {:else if newChType === 'telegram'}
        <div class="grid grid-cols-2 gap-4">
          <div class="space-y-2">
            <Label for="nc-bot">Bot token</Label>
            <Input id="nc-bot" type="password" bind:value={newChBotToken} autocomplete="new-password" class="font-mono" />
          </div>
          <div class="space-y-2">
            <Label for="nc-chat">Chat ID</Label>
            <Input id="nc-chat" bind:value={newChChatId} placeholder="e.g. -100123456789" class="font-mono" />
          </div>
        </div>
        <p class="text-xs text-muted-foreground">Create a bot via @BotFather, add it to the chat, and paste the chat ID.</p>
      {:else}
        <div class="grid grid-cols-[1fr_100px] gap-4">
          <div class="space-y-2">
            <Label for="nc-host">SMTP host</Label>
            <Input id="nc-host" bind:value={newChHost} class="font-mono" />
          </div>
          <div class="space-y-2">
            <Label for="nc-port">Port</Label>
            <Input id="nc-port" bind:value={newChPort} inputmode="numeric" class="font-mono" />
          </div>
        </div>
        <div class="grid grid-cols-2 gap-4">
          <div class="space-y-2">
            <Label for="nc-user">Username</Label>
            <Input id="nc-user" bind:value={newChUser} autocomplete="username" class="font-mono" />
          </div>
          <div class="space-y-2">
            <Label for="nc-pass">Password</Label>
            <Input id="nc-pass" type="password" bind:value={newChPass} autocomplete="new-password" class="font-mono" />
          </div>
        </div>
        <div class="grid grid-cols-[1fr_2fr] gap-4">
          <div class="space-y-2">
            <Label for="nc-from">From</Label>
            <Input id="nc-from" bind:value={newChFrom} class="font-mono" />
          </div>
          <div class="space-y-2">
            <Label for="nc-to">To</Label>
            <Input id="nc-to" bind:value={newChTo} placeholder="comma-separated" class="font-mono" />
          </div>
        </div>
      {/if}
    </div>
    <Dialog.Footer>
      <Button variant="outline" onclick={() => (showCreateChannel = false)}>Cancel</Button>
      <Button onclick={createChannel} disabled={!newChName}>Add</Button>
    </Dialog.Footer>
  </Dialog.Content>
</Dialog.Root>

<!-- destructive confirmation -->
{#if pending}
  <ConfirmCode
    bind:open={confirmOpen}
    title={pending.title}
    description={pending.description}
    confirmLabel={pending.confirmLabel}
    onConfirm={pending.run}
  />
{/if}
