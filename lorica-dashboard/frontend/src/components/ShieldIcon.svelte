<script lang="ts">
  interface Props {
    size?: number;
  }

  let { size = 32 }: Props = $props();
</script>

<svg viewBox="0 0 32 32" fill="none" width={size} height={size}>
  <path d="M16 2L4 8v8c0 7.2 5.1 13.9 12 16 6.9-2.1 12-8.8 12-16V8L16 2z" fill="#3b82f6" stroke="#2563eb" stroke-width="1"/>
  <path d="M16 6l-8 4v6c0 5.2 3.4 10 8 11.6 4.6-1.6 8-6.4 8-11.6v-6l-8-4z" fill="#60a5fa"/>
  <path d="M14 15l-2-2-1.5 1.5L14 18l6-6-1.5-1.5L14 15z" fill="white"/>
</svg>
