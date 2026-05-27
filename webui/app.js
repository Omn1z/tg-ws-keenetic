(function () {
    'use strict';

    const $ = (sel) => document.querySelector(sel);

    const els = {
        statusPill: $('#status-pill'),
        version:    $('#version'),
        link:       $('#link'),
        copyLink:   $('#copy-link'),
        stats:      $('#stats'),
        form:       $('#cfg'),
        saveResult: $('#save-result'),
        reload:     $('#reload-cfg'),
        restart:    $('#btn-restart'),
        newSecret:  $('#btn-new-secret'),
    };

    let lastConfig = null;

    async function api(method, path, body) {
        const headers = {};
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        const res = await fetch(path, {
            method,
            headers,
            body: body !== undefined ? JSON.stringify(body) : undefined,
            credentials: 'same-origin',
        });
        const text = await res.text();
        let parsed;
        try { parsed = text ? JSON.parse(text) : null; } catch { parsed = { error: text }; }
        if (!res.ok) {
            const msg = parsed && parsed.error ? parsed.error : `HTTP ${res.status}`;
            throw new Error(msg);
        }
        return parsed;
    }

    function setResult(text, kind) {
        els.saveResult.textContent = text;
        els.saveResult.className = 'result' + (kind ? ' ' + kind : '');
        if (kind) {
            setTimeout(() => { els.saveResult.textContent = ''; els.saveResult.className = 'result'; }, 4500);
        }
    }

    function applyState(state) {
        lastConfig = state.config;

        els.statusPill.textContent = state.listening ? 'online' : 'offline';
        els.statusPill.className   = 'pill ' + (state.listening ? 'pill-on' : 'pill-off');
        els.version.textContent    = state.version ? 'v' + state.version : '';
        els.link.textContent       = state.link || '';

        renderStats(state.stats);
        fillForm(state.config);
    }

    function renderStats(s) {
        if (!s) { els.stats.innerHTML = ''; return; }
        const c = s.connections || {};
        const t = s.traffic || {};
        const w = s.ws || {};
        const lines = [
            ['Всего соединений', c.total],
            ['Активные',         c.active],
            ['Через WebSocket',  c.ws],
            ['Через TCP fallback', c.tcp_fallback],
            ['Через Cloudflare', c.cfproxy],
            ['Замаскированные',  c.masked],
            ['Не прошли auth',   c.bad],
            ['Ошибок WS',        w.errors],
            ['Pool hit/miss',    `${w.pool_hits || 0} / ${w.pool_misses || 0}`],
            ['Передано',         t.human_up],
            ['Получено',         t.human_down],
        ];
        els.stats.innerHTML = lines
            .map(([k, v]) => `<li><b>${k}</b><span>${v == null ? '0' : v}</span></li>`)
            .join('');
    }

    function fillForm(cfg) {
        if (!cfg) return;
        for (const [name, value] of Object.entries(cfg)) {
            const field = els.form.elements.namedItem(name);
            if (!field) continue;
            if (field.type === 'checkbox') {
                field.checked = !!value;
            } else if (name === 'dc_redirects') {
                field.value = Object.entries(value)
                    .map(([dc, ip]) => `${dc}: ${ip}`).join('\n');
            } else {
                field.value = value == null ? '' : value;
            }
        }
    }

    function readForm() {
        const data = {};
        for (const el of els.form.elements) {
            if (!el.name) continue;
            if (el.type === 'checkbox') {
                data[el.name] = el.checked;
            } else if (el.name === 'dc_redirects') {
                data[el.name] = parseDcMap(el.value);
            } else if (el.type === 'number') {
                data[el.name] = el.value === '' ? 0 : Number(el.value);
            } else {
                data[el.name] = el.value;
            }
        }
        return data;
    }

    function parseDcMap(text) {
        const map = {};
        for (const line of text.split(/[\r\n,;]+/)) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            const m = trimmed.match(/^(\d+)\s*[:=]\s*([0-9.]+)$/);
            if (m) map[m[1]] = m[2];
        }
        return map;
    }

    async function refresh() {
        try {
            const state = await api('GET', '/api/state');
            applyState(state);
        } catch (e) {
            setResult('Ошибка получения статуса: ' + e.message, 'bad');
        }
    }

    els.form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = readForm();
        setResult('Сохраняю и перезапускаю…');
        try {
            await api('POST', '/api/config', payload);
            setResult('Сохранено. Перезапуск…', 'ok');
            setTimeout(refresh, 1500);
        } catch (err) {
            setResult('Не сохранено: ' + err.message, 'bad');
        }
    });

    els.reload.addEventListener('click', () => {
        fillForm(lastConfig);
        setResult('Изменения отменены', 'ok');
    });

    els.restart.addEventListener('click', async () => {
        setResult('Перезапускаю…');
        try {
            await api('POST', '/api/restart');
            setResult('Перезапуск отправлен', 'ok');
            setTimeout(refresh, 1500);
        } catch (err) {
            setResult('Не удалось: ' + err.message, 'bad');
        }
    });

    els.newSecret.addEventListener('click', async () => {
        if (!confirm('Сгенерировать новый секрет? Старые ссылки перестанут работать.')) return;
        setResult('Генерирую секрет…');
        try {
            await api('POST', '/api/secret');
            setResult('Секрет обновлён', 'ok');
            setTimeout(refresh, 1500);
        } catch (err) {
            setResult('Не удалось: ' + err.message, 'bad');
        }
    });

    els.copyLink.addEventListener('click', async () => {
        const text = els.link.textContent || '';
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            els.copyLink.textContent = 'Скопировано';
            setTimeout(() => { els.copyLink.textContent = 'Скопировать'; }, 1400);
        } catch {
            const range = document.createRange();
            range.selectNode(els.link);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
        }
    });

    refresh();
    setInterval(refresh, 5000);
})();
