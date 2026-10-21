<script lang="ts">
  import * as Sidebar from '#components/ui/sidebar/index.js';
  import { KeyRound, KeySquare, Bell, ScrollText, LogOut, ShieldCheck } from 'lucide-svelte';

  let {
    tab,
    keyCount,
    upstreamCount,
    channelCount,
    onselect,
    onlogout
  }: {
    tab: string;
    keyCount: number;
    upstreamCount: number;
    channelCount: number;
    onselect: (t: 'keys' | 'upstreams' | 'notify' | 'audit') => void;
    onlogout: () => void;
  } = $props();

  const items = $derived([
    { id: 'keys' as const, label: 'Sub-keys', icon: KeyRound, badge: keyCount },
    { id: 'upstreams' as const, label: 'God keys', icon: KeySquare, badge: upstreamCount },
    { id: 'notify' as const, label: 'Notifications', icon: Bell, badge: channelCount },
    { id: 'audit' as const, label: 'Audit logs', icon: ScrollText, badge: null as number | null }
  ]);
</script>

<Sidebar.Root collapsible="icon">
  <Sidebar.Header>
    <Sidebar.Menu>
      <Sidebar.MenuItem>
        <div class="flex items-center gap-2 px-2 py-1">
          <span class="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheck size={16} />
          </span>
          <span class="grid flex-1 text-left leading-tight">
            <span class="truncate text-sm font-semibold">sevshield</span>
            <span class="truncate text-xs text-muted-foreground">API key proxy</span>
          </span>
        </div>
      </Sidebar.MenuItem>
    </Sidebar.Menu>
  </Sidebar.Header>
  <Sidebar.Content>
    <Sidebar.Group>
      <Sidebar.GroupLabel>Manage</Sidebar.GroupLabel>
      <Sidebar.GroupContent>
        <Sidebar.Menu>
          {#each items as it (it.id)}
            <Sidebar.MenuItem>
              <Sidebar.MenuButton
                isActive={tab === it.id}
                onclick={() => onselect(it.id)}
                tooltipContent={it.label}
              >
                <it.icon />
                <span>{it.label}</span>
              </Sidebar.MenuButton>
              {#if it.badge !== null}
                <Sidebar.MenuBadge>{it.badge}</Sidebar.MenuBadge>
              {/if}
            </Sidebar.MenuItem>
          {/each}
        </Sidebar.Menu>
      </Sidebar.GroupContent>
    </Sidebar.Group>
  </Sidebar.Content>
  <Sidebar.Footer>
    <Sidebar.Menu>
      <Sidebar.MenuItem>
        <div class="flex items-center gap-2 rounded-lg border px-2 py-1.5">
          <span class="grid flex-1 text-left leading-tight">
            <span class="truncate text-xs font-medium">Administrator</span>
            <span class="truncate text-xs text-muted-foreground">session active</span>
          </span>
          <Sidebar.MenuButton onclick={onlogout} tooltipContent="Sign out" size="sm" class="w-auto px-2">
            <LogOut />
            <span class="sr-only">Sign out</span>
          </Sidebar.MenuButton>
        </div>
      </Sidebar.MenuItem>
    </Sidebar.Menu>
  </Sidebar.Footer>
</Sidebar.Root>
