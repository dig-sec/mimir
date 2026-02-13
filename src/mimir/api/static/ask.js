import { toast, apiFetch, apiUrl } from './helpers.js';

/* ── entity-type dot color class ────────── */
function typeClass(t) {
  return 't-' + (t || 'unknown');
}

/* ── markdown-lite renderer ─────────────── */
function renderMarkdown(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    /* headers */
    .replace(/^### (.+)$/gm, '<h4>$1</h4>')
    .replace(/^## (.+)$/gm, '<h3>$1</h3>')
    .replace(/^# (.+)$/gm, '<h2>$1</h2>')
    /* bold / italic */
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    /* inline code */
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    /* unordered lists */
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, m => '<ul>' + m + '</ul>')
    /* line breaks */
    .replace(/\n{2,}/g, '</p><p>')
    .replace(/\n/g, '<br/>')
    .replace(/^/, '<p>')
    .replace(/$/, '</p>')
    /* clean up empty paragraphs */
    .replace(/<p>\s*<\/p>/g, '')
    .replace(/<p>\s*(<h[234]>)/g, '$1')
    .replace(/(<\/h[234]>)\s*<\/p>/g, '$1')
    .replace(/<p>\s*(<ul>)/g, '$1')
    .replace(/(<\/ul>)\s*<\/p>/g, '$1');
}

/* ── escape HTML ─────────────────────────── */
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

export function initAsk() {
  const messages  = document.getElementById('askMessages');
  const input     = document.getElementById('askInput');
  const sendBtn   = document.getElementById('askSendBtn');
  if (!messages || !input || !sendBtn) return;

  let isStreaming = false;

  /* ── auto-resize textarea ──────────────── */
  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 160) + 'px';
  });

  /* ── keyboard shortcuts ────────────────── */
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendQuestion();
    }
  });

  sendBtn.addEventListener('click', () => sendQuestion());

  /* ── suggestion buttons ────────────────── */
  document.querySelectorAll('.ask-suggestion').forEach(btn => {
    btn.addEventListener('click', () => {
      input.value = btn.dataset.q;
      input.dispatchEvent(new Event('input'));
      sendQuestion();
    });
  });

  /* ── send question ─────────────────────── */
  async function sendQuestion() {
    const question = input.value.trim();
    if (!question || isStreaming) return;

    isStreaming = true;
    sendBtn.disabled = true;
    input.value = '';
    input.style.height = 'auto';

    /* remove welcome screen on first question */
    const welcome = messages.querySelector('.ask-welcome');
    if (welcome) welcome.remove();

    /* add user message */
    const userMsg = document.createElement('div');
    userMsg.className = 'ask-msg ask-msg-user';
    userMsg.innerHTML = `<div class="ask-msg-content">${esc(question)}</div>`;
    messages.appendChild(userMsg);

    /* add assistant message placeholder */
    const assistantMsg = document.createElement('div');
    assistantMsg.className = 'ask-msg ask-msg-assistant';
    assistantMsg.innerHTML = `
      <div class="ask-msg-sources" id="askCurrentSources" style="display:none"></div>
      <div class="ask-msg-content"><span class="ask-thinking">Searching knowledge graph…</span></div>
    `;
    messages.appendChild(assistantMsg);
    scrollToBottom();

    const contentEl = assistantMsg.querySelector('.ask-msg-content');
    const sourcesEl = assistantMsg.querySelector('.ask-msg-sources');

    try {
      const resp = await fetch(apiUrl('/api/ask'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question }),
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.detail || `Request failed (${resp.status})`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let fullText = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (!raw) continue;

          let event;
          try { event = JSON.parse(raw); } catch { continue; }

          if (event.type === 'sources') {
            /* Show context summary */
            renderSources(sourcesEl, event);
            contentEl.innerHTML = '<span class="ask-thinking">Generating answer…</span>';
            scrollToBottom();
          } else if (event.type === 'token') {
            if (contentEl.querySelector('.ask-thinking')) {
              contentEl.innerHTML = '';
            }
            fullText += event.content;
            contentEl.innerHTML = renderMarkdown(fullText);
            scrollToBottom();
          } else if (event.type === 'done') {
            /* final render with full markdown */
            contentEl.innerHTML = renderMarkdown(fullText);
            scrollToBottom();
          } else if (event.type === 'error') {
            contentEl.innerHTML = `<div class="ask-error">${esc(event.message)}</div>`;
            scrollToBottom();
          }
        }
      }

      /* If we never got any tokens */
      if (!fullText && contentEl.querySelector('.ask-thinking')) {
        contentEl.innerHTML = '<div class="ask-error">No response received from Ollama.</div>';
      }

    } catch (err) {
      contentEl.innerHTML = `<div class="ask-error">${esc(err.message)}</div>`;
      toast(err.message, 'error');
    } finally {
      isStreaming = false;
      sendBtn.disabled = false;
      input.focus();
      scrollToBottom();
    }
  }

  /* ── render source context chips ───────── */
  function renderSources(el, event) {
    if (!event.entities_found && !event.relations_found) {
      el.innerHTML = '<div class="ask-source-empty">No matching entities found in the knowledge graph.</div>';
      el.style.display = '';
      return;
    }

    let html = '<div class="ask-source-summary">';
    html += `<span class="ask-source-stat">🔍 ${event.entities_found} entities</span>`;
    html += `<span class="ask-source-stat">🔗 ${event.relations_found} relations</span>`;
    html += `<span class="ask-source-stat">📄 ${event.provenance_found} sources</span>`;
    html += '</div>';

    if (event.entities && event.entities.length) {
      html += '<div class="ask-source-entities">';
      for (const e of event.entities.slice(0, 8)) {
        html += `<span class="ask-entity-chip"><span class="entity-dot ${typeClass(e.type)}"></span>${esc(e.name)}<span class="ask-chip-type">${esc(e.type || '')}</span></span>`;
      }
      if (event.entities_found > 8) {
        html += `<span class="ask-entity-chip ask-chip-more">+${event.entities_found - 8} more</span>`;
      }
      html += '</div>';
    }

    el.style.display = '';
    el.innerHTML = html;
  }

  function scrollToBottom() {
    messages.scrollTop = messages.scrollHeight;
  }
}
