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
        updCurrent: $('#update-current'),
        updLatest:  $('#update-latest'),
        updPublished: $('#update-published'),
        updNotes:   $('#update-notes'),
        updResult:  $('#update-result'),
        updCheck:   $('#btn-update-check'),
        updApply:   $('#btn-update-apply'),
    };

    let lastUpdateInfo = null;

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

    function setUpdateResult(text, kind) {
        els.updResult.textContent = text;
        els.updResult.className = 'result' + (kind ? ' ' + kind : '');
    }

    function applyUpdateInfo(info) {
        lastUpdateInfo = info;
        els.updCurrent.textContent = info.current || '—';
        if (info.available) {
            els.updLatest.textContent = `${info.latest} (${info.channel})`;
            els.updLatest.className = 'has-update';
            els.updApply.disabled = false;
        } else {
            els.updLatest.textContent = `${info.latest} — актуальна`;
            els.updLatest.className = 'up-to-date';
            els.updApply.disabled = true;
        }
        els.updPublished.textContent = info.published_at
            ? `опубликовано: ${info.published_at}` : '';
        if (info.notes) {
            els.updNotes.textContent = info.notes;
            els.updNotes.hidden = false;
        } else {
            els.updNotes.hidden = true;
        }
    }

    els.updCheck.addEventListener('click', async () => {
        setUpdateResult('Проверяю GitHub…');
        els.updCheck.disabled = true;
        try {
            const info = await api('GET', '/api/update');
            applyUpdateInfo(info);
            setUpdateResult(
                info.available ? 'Доступна новая версия' : 'У вас актуальная версия',
                info.available ? '' : 'ok'
            );
        } catch (e) {
            setUpdateResult('Не удалось проверить: ' + e.message, 'bad');
        } finally {
            els.updCheck.disabled = false;
        }
    });

    els.updApply.addEventListener('click', async () => {
        if (!lastUpdateInfo || !lastUpdateInfo.available) return;
        if (!confirm(
            `Обновиться с ${lastUpdateInfo.current} до ${lastUpdateInfo.latest}? ` +
            'Сервис будет перезапущен. Конфигурация сохранится.'
        )) return;
        setUpdateResult('Скачиваю обновление…');
        els.updApply.disabled = true;
        try {
            const res = await api('POST', '/api/update');
            if (res.applied) {
                setUpdateResult(
                    `Обновление ${res.from} → ${res.to} запущено. ` +
                    'Через 5–10 секунд сервис перезапустится.',
                    'ok'
                );
                setTimeout(() => location.reload(), 12000);
            } else {
                setUpdateResult(res.reason || 'Нет обновлений', 'ok');
                els.updApply.disabled = false;
            }
        } catch (e) {
            setUpdateResult('Ошибка установки: ' + e.message, 'bad');
            els.updApply.disabled = false;
        }
    });

    refresh();
    setInterval(refresh, 5000);
})();
