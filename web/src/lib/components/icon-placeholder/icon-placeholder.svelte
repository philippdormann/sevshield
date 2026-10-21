<script lang="ts" module>
	import {
		Check as CheckIcon,
		ChevronDown as ChevronDownIcon,
		ChevronUp as ChevronUpIcon,
		Minus as MinusIcon,
		PanelLeft as PanelLeftIcon,
		X as XIcon,
		type Icon as IconType
	} from "lucide-svelte";

	const icons: Record<string, typeof XIcon> = {
		CheckIcon,
		ChevronDownIcon,
		ChevronUpIcon,
		MinusIcon,
		PanelLeftIcon,
		XIcon
	};
</script>

<script lang="ts">
	let {
		lucide,
		tabler,
		hugeicons,
		phosphor,
		remixicon,
		class: className,
		...restProps
	}: {
		lucide?: string;
		tabler?: string;
		hugeicons?: string;
		phosphor?: string;
		remixicon?: string;
		class?: string;
	} = $props();
	const Icon = $derived(lucide ? icons[lucide] : undefined);
</script>

{#if Icon}
	<Icon class={className} {...restProps} />
{/if}
