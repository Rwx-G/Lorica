<script lang="ts">
  interface Props {
    configText: string;
    onCancel: () => void;
    onParse: () => void;
  }

  let { configText = $bindable(), onCancel, onParse }: Props = $props();
</script>

<div class="step-content">
  <p class="step-hint">Paste your Nginx <code>server {'{}'}</code> and <code>upstream {'{}'}</code> blocks below.</p>
  <textarea
    class="config-textarea"
    bind:value={configText}
    placeholder={'server \n    listen 80;\n    server_name example.com;\n    location / {  \n        proxy_pass http://127.0.0.1:8080;\n    }\n}'}
    rows="22"
    spellcheck="false"
  ></textarea>
  <div class="step-actions">
    <button class="btn btn-ghost" onclick={onCancel}>Cancel</button>
    <button
      class="btn btn-primary"
      disabled={!configText.trim()}
      onclick={onParse}
    >Parse & Analyze</button>
  </div>
</div>
