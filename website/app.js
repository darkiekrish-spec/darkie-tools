/* Darkie Tools — anime night: live scan console + particle map + playground */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const statusEl = $('status');

  /* ---------------- helpers ---------------- */
  function setStatus(txt) { if (statusEl) statusEl.textContent = txt; }
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  async function typeLine(el, text, cls, speed = 8) {
    const p = document.createElement('p');
    p.className = 'line' + (cls ? ' ' + cls : '');
    el.appendChild(p);
    for (let i = 0; i <= text.length; i++) {
      p.textContent = text.slice(0, i);
      el.scrollTop = el.scrollHeight;
      await sleep(speed);
    }
    return p;
  }

  function appendLine(el, text, cls) {
    const p = document.createElement('p');
    p.className = 'line' + (cls ? ' ' + cls : '');
    p.textContent = text;
    el.appendChild(p);
    el.scrollTop = el.scrollHeight;
    return p;
  }

  /* ---------------- background video: graceful fallback ---------------- */
  (function initVideo() {
    const v = $('bg-video');
    if (!v) return;
    if (reduceMotion) { v.classList.add('hidden'); return; }
    let resolved = false;
    v.addEventListener('loadeddata', () => { v.classList.remove('hidden'); resolved = true; });
    v.addEventListener('error', () => { if (!resolved) { v.classList.add('hidden'); startParticles(true); } }, { once: true });
    v.addEventListener('canplaythrough', () => { v.classList.remove('hidden'); resolved = true; });
    // if the video hangs (blank poster) give the particles a boost after 3s
    setTimeout(() => { if (!resolved) { v.classList.add('hidden'); startParticles(true); } }, 3000);
  })();

  /* ---------------- particle connection map ---------------- */
  let particleCtx = null, pw = 0, ph = 0, particles = [], running = false;
  function startParticles(force) {
    const canvas = $('particles');
    if (!canvas) return;
    if (!force && !reduceMotion) return; // keep the video as the star by default
    if (running) return;
    running = true;
    const ctx = particleCtx = canvas.getContext('2d');
    const resize = () => { pw = canvas.width = window.innerWidth; ph = canvas.height = window.innerHeight; };
    resize(); window.addEventListener('resize', resize);
    const N = Math.min(90, Math.floor((pw * ph) / 16000));
    const colors = ['255,47,146', '95,240,255', '255,209,102'];
    particles = Array.from({ length: N }, () => ({
      x: Math.random() * pw, y: Math.random() * ph,
      vx: (Math.random() - 0.5) * 0.5, vy: (Math.random() - 0.5) * 0.5,
      r: Math.random() * 1.6 + 0.6,
      c: colors[Math.floor(Math.random() * colors.length)],
    }));
    function draw() {
      ctx.clearRect(0, 0, pw, ph);
      for (const p of particles) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > pw) p.vx *= -1;
        if (p.y < 0 || p.y > ph) p.vy *= -1;
      }
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const a = particles[i], b = particles[j];
          const dx = a.x - b.x, dy = a.y - b.y;
          const d = dx * dx + dy * dy;
          if (d < 16000) {
            const alpha = (1 - d / 16000) * 0.5;
            ctx.strokeStyle = `rgba(${a.c},${alpha})`;
            ctx.lineWidth = 0.6;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }
      for (const p of particles) {
        ctx.fillStyle = `rgba(${p.c},0.8)`;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
      }
      if (!reduceMotion) requestAnimationFrame(draw);
    }
    draw();
  }

  /* ---------------- hero: live self-scan ---------------- */
  async function runSelfScan() {
    const out = $('scan-output');
    if (!out) return;
    await typeLine(out, '$ darkie-tools --scan --target self', 'dim', 5);
    await sleep(300);
    const step1 = appendLine(out, '✓ resolving public endpoint…', '');
    setStatus('scanning…');

    const providers = [
      {
        url: 'https://ipwho.is/',
        parse: (d) => ({
          ok: !!(d && d.success !== false && d.ip),
          ip: d.ip,
          loc: [d.city, d.region, d.country].filter(Boolean).join(', '),
          isp: (d.connection && d.connection.isp) || '',
          asn: (d.connection && d.connection.asn ? `AS${d.connection.asn}` : '') || '',
        }),
      },
      {
        url: 'https://api.ipify.org?format=json',
        parse: (d) => ({ ok: !!(d && d.ip), ip: d.ip, loc: '', isp: '', asn: '' }),
      },
    ];
    let info = null;
    for (const p of providers) {
      try {
        const r = await fetch(p.url, { signal: AbortSignal.timeout(8000) });
        info = p.parse(await r.json());
        if (info.ok) break;
      } catch (e) { /* try next */ }
    }
    if (info && info.ok) {
      await sleep(400);
      step1.textContent = '✓ public endpoint resolved';
      appendLine(out, '', '');
      appendLine(out, `  ip        ${info.ip}`, '');
      appendLine(out, `  location  ${info.loc || '—'}`, '');
      appendLine(out, `  isp       ${info.isp || '—'}`, '');
      appendLine(out, `  asn       ${info.asn || '—'}`, 'meta');
      appendLine(out, '✓ direct connection', 'ok');
    } else {
      step1.textContent = '— offline: showing simulated scan';
      await simulateFallbackScan(out);
    }
    appendLine(out, '✓ 17 modules ready', 'ok');
    setStatus('online');
  }

  async function simulateFallbackScan(out) {
    appendLine(out, '', '');
    appendLine(out, '  ip        203.0.113.42 (simulated)', '');
    appendLine(out, '  location  —, — (simulated)', '');
    appendLine(out, '  isp       darkie-testnet', '');
  }

  /* ---------------- typewriter headline with glitch ---------------- */
  const phrases = ['monitor.', 'recon.', 'harden.', 'attack surface.', 'defend.', 'report.'];
  let pi = 0, ci = 0, deleting = false;
  const typeEl = $('typewriter');
  function typeTick() {
    if (!typeEl) return;
    const word = phrases[pi];
    if (deleting) {
      ci--;
      if (ci <= 0) { deleting = false; pi = (pi + 1) % phrases.length; }
    } else {
      ci++;
      if (ci >= word.length) {
        deleting = true;
        typeEl.classList.remove('glitching');
        setTimeout(typeTick, 1500);
        return;
      }
      if (ci > word.length * 0.6) typeEl.classList.add('glitching');
    }
    typeEl.textContent = word.slice(0, ci) + (deleting ? '' : '▌');
    setTimeout(typeTick, deleting ? 38 : 88);
  }
  if (typeEl) setTimeout(typeTick, 800);

  /* ---------------- console tilt on hover ---------------- */
  const consoleEl = $('scan-console');
  if (consoleEl && !reduceMotion) {
    consoleEl.addEventListener('mousemove', (e) => {
      const r = consoleEl.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width - 0.5;
      const py = (e.clientY - r.top) / r.height - 0.5;
      consoleEl.style.transform = `perspective(900px) rotateY(${px * 8}deg) rotateX(${-py * 8}deg) translateZ(0)`;
    });
    consoleEl.addEventListener('mouseleave', () => { consoleEl.style.transform = ''; });
  }

  /* ---------------- log tape ---------------- */
  const tapeLines = [
    '  [00:00:01]  packet captured · tcp 443 → 10.0.0.4', '  [00:00:02]  arp · new device 192.168.0.19',
    '  [00:00:04]  osint · 12 hosts resolved', '  [00:00:06]  cve-2024-XXXX · patched',
    '  [00:00:08]  ssh brute-force · blocked 214.16.8.9', '  [00:00:11]  report → report_20260802.html',
    '  [00:00:13]  wifi · wpa2 · handshake captured', '  [00:00:15]  endpoint · 4 processes flagged',
    '  [00:00:18]  pentest · sqli payload filtered', '  [00:00:21]  stress · 1,240 req/s sustained',
    '  [00:00:24]  kernel · aslr enabled · syncookies on', '  [00:00:27]  siem · alert threshold reached',
  ];
  function startLogTape() {
    const inner = $('logtape-inner');
    if (!inner) return;
    inner.innerHTML = tapeLines.join('') + tapeLines.join('') + tapeLines.join('');
    const len = tapeLines.join('').length;
    inner.style.animation = `tape 38s linear infinite`;
    const sheet = document.createElement('style');
    sheet.textContent = `@keyframes tape{from{transform:translateX(0)}to{transform:translateX(-${len}ch)}}`;
    document.head.appendChild(sheet);
  }

  /* ---------------- animated counters ---------------- */
  function animateCount(el) {
    const target = parseInt(el.dataset.target, 10);
    const dur = 1400;
    const t0 = performance.now();
    function step(now) {
      const p = Math.min((now - t0) / dur, 1);
      el.textContent = Math.floor(target * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  document.querySelectorAll('.stat-num').forEach(animateCount);

  /* ---------------- scroll reveal ---------------- */
  const io = new IntersectionObserver((entries) => {
    entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
  }, { threshold: 0.12 });
  document.querySelectorAll('.p-row, .code-block, .note').forEach(el => {
    el.classList.add('reveal');
    io.observe(el);
  });

  /* ---------------- scroll progress ---------------- */
  const prog = $('scroll-progress');
  window.addEventListener('scroll', () => {
    const h = document.documentElement.scrollHeight - window.innerHeight;
    prog.style.width = (h > 0 ? (window.scrollY / h) * 100 : 0) + '%';
  }, { passive: true });

  /* ---------------- playground: runs the REAL tool via the local server ---------------- */
  const play = $('play-output');

  async function callBackend(tool, args) {
    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, args }),
      });
      return await res.json();
    } catch (err) {
      return { exit: 1, output: 'error: cannot reach the local server. Start it with:\n  ./website/serve.sh' };
    }
  }

  async function runTool(tool, args) {
    appendLine(play, `$ ./tool.sh --run ${tool} ${args.join(' ')}`, 'meta');
    appendLine(play, '', '');
    const { exit, output } = await callBackend(tool, args);
    const lines = String(output || '').split('\n');
    for (const raw of lines) {
      const line = raw.replace(/\s+$/, '');
      if (!line) continue;
      if (line.includes('Querying') || line.includes('Enumerating') || line.includes('resolving')) {
        await typeLine(play, line, 'dim', 3);
      } else if (/error|failed|refused|timed out/i.test(line)) {
        appendLine(play, line, 'err');
      } else if (/(open|✓|scan complete|found|location|asn|isp|IP:|TZ:|CVE|saved)/i.test(line)) {
        appendLine(play, line, 'ok');
      } else {
        appendLine(play, line, '');
      }
    }
    appendLine(play, '', '');
    appendLine(play, exit === 0 ? '✓ done (exit 0)' : `! tool returned exit ${exit}`, exit === 0 ? 'ok' : 'err');
    appendLine(play, '', '');
  }

  async function showTools() {
    let tools;
    try {
      const res = await fetch('/api/tools');
      tools = await res.json();
    } catch (e) { tools = []; }
    if (!tools.length) {
      appendLine(play, 'no tools available — start the server with ./website/serve.sh', 'err');
      return;
    }
    appendLine(play, 'tools you can run:', 'meta');
    for (const t of tools) {
      appendLine(play, `  ${t.name.padEnd(22)} ${t.desc}`, '');
    }
  }

  async function runCommand(raw) {
    const parts = raw.trim().split(/\s+/);
    const cmd = (parts[0] || '').toLowerCase();
    if (!cmd) return;
    appendLine(play, `> ${raw}`, 'meta');
    switch (cmd) {
      case 'help':
        ['  tools                    list runnable tools', '  run <tool> [args...]       run one tool against the real CLI',
         '  osint 8.8.8.8            shortcut: real IP geolocation', '  hash <text>               shortcut: real hash generator',
         '  cve <id>                 shortcut: real CVE lookup', '  scan <host>               shortcut: real port scan',
         '  clear                    clear terminal'].forEach(l => appendLine(play, l, 'dim'));
        break;
      case 'tools':
        await showTools();
        break;
      case 'run':
        const toolName = parts[1];
        if (!toolName) { appendLine(play, 'usage: run <tool> [args...] (see: tools)', 'err'); break; }
        await runTool(toolName, parts.slice(2));
        break;
      case 'osint':
        await runTool('osint_ipgeo', parts.slice(1));
        break;
      case 'hash':
        await runTool('hash_generator', parts.slice(1));
        break;
      case 'cve':
        await runTool('vuln_cve_lookup', parts.slice(1));
        break;
      case 'scan':
        await runTool('legacy_portscan', parts.slice(1));
        break;
      case 'clear': play.innerHTML = ''; break;
      default: appendLine(play, `unknown command: ${cmd} (try help)`, 'err');
    }
  }

  const input = $('play-cmd');
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { runCommand(input.value); input.value = ''; }
  });
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => runCommand(chip.dataset.cmd));
  });

  /* copy buttons */
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const el = $(btn.dataset.target);
      const text = el.textContent.trim();
      try { await navigator.clipboard.writeText(text); }
      catch (e) {
        const ta = document.createElement('textarea');
        ta.value = text; document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); ta.remove();
      }
      btn.textContent = 'copied ✓';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1600);
    });
  });

  /* ---------------- boot ---------------- */
  appendLine(play, 'Live playground — runs the REAL tool via v4/tool.sh.', '');
  appendLine(play, 'Type help to get started, or tap a chip below.', 'dim');
  (async () => {
    try {
      const r = await fetch('/api/tools');
      if (r.status === 200) {
        const tools = await r.json();
        appendLine(play, `${tools.length} tools available through the local server.`, 'ok');
      } else {
        appendLine(play, 'server offline — start it with: ./website/serve.sh', 'err');
      }
    } catch (err) { appendLine(play, 'server offline — start it with: ./website/serve.sh', 'err'); }
  })();
  runSelfScan();
  startLogTape();
})();
