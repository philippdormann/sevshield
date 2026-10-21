<script lang="ts">
	import * as AlertDialog from '#components/ui/alert-dialog/index.js';
	import { Button } from '#components/ui/button/index.js';
	import { Input } from '#components/ui/input/index.js';

	let {
		open = $bindable(false),
		title,
		description,
		confirmLabel = 'Confirm',
		onConfirm
	}: {
		open: boolean;
		title: string;
		description: string;
		confirmLabel?: string;
		onConfirm: () => void | Promise<void>;
	} = $props();

	let code = $state('');
	let expected = $state('');

	$effect(() => {
		if (open) {
			expected = String(Math.floor(100000 + Math.random() * 900000));
			code = '';
		}
	});

	async function confirm() {
		if (code.trim() !== expected) return;
		open = false;
		await onConfirm();
	}
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content size="sm">
		<AlertDialog.Header>
			<AlertDialog.Title>{title}</AlertDialog.Title>
			<AlertDialog.Description>
				{description}
				Type <span class="font-mono font-bold text-foreground">{expected}</span> to confirm.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<Input
			bind:value={code}
			inputmode="numeric"
			maxlength={6}
			placeholder="6-digit code"
			autocomplete="off"
			class="font-mono tracking-widest"
		/>
		<AlertDialog.Footer>
			<Button variant="outline" onclick={() => (open = false)}>Cancel</Button>
			<Button variant="destructive" disabled={code.trim() !== expected} onclick={confirm}>
				{confirmLabel}
			</Button>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
