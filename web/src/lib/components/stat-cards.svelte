<script lang="ts">
  import * as Card from '#components/ui/card/index.js';

  let {
    stats
  }: {
    stats: { label: string; value: string | number; sub: string }[];
  } = $props();
</script>

<div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
  {#each stats as s (s.label)}
    <Card.Root>
      <Card.Header>
        <Card.Description>{s.label}</Card.Description>
        <Card.Title class="text-2xl font-semibold tabular-nums">{s.value}</Card.Title>
        <Card.Description class="text-xs">{s.sub}</Card.Description>
      </Card.Header>
    </Card.Root>
  {/each}
</div>
