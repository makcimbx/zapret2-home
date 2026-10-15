'use strict';
// Local mock only. Uses upstream LuCI tabs + Bootstrap CSS, never router credentials/RPC.
// node tests/frontend.browser.js -- Playwright Chromium, or CHROME_PATH, required.
// LUCI_UI_FILE / LUCI_CSS_FILE / LUCI_MOBILE_CSS_FILE allow offline cached upstream assets.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'files/www/luci-static/resources/view/services/zapret2home.js'), 'utf8');
const base = 'https://raw.githubusercontent.com/openwrt/luci/master/';
async function asset(env, url) {
	const configured = process.env[env] || process.env[{ LUCI_UI_FILE: 'LUCI_UI_SOURCE', LUCI_CSS_FILE: 'LUCI_CASCADE_SOURCE', LUCI_MOBILE_CSS_FILE: 'LUCI_MOBILE_SOURCE' }[env]];
	if (configured) return fs.readFileSync(configured, 'utf8');
	const response = await fetch(base + url);
	assert.equal(response.ok, true, 'Cannot download upstream LuCI asset');
	return response.text();
}
async function main() {
	const [uiSource, css, mobileCss] = await Promise.all([
		asset('LUCI_UI_FILE', 'modules/luci-base/htdocs/luci-static/resources/ui.js'),
		asset('LUCI_CSS_FILE', 'themes/luci-theme-bootstrap/htdocs/luci-static/bootstrap/cascade.css'),
		asset('LUCI_MOBILE_CSS_FILE', 'themes/luci-theme-bootstrap/htdocs/luci-static/bootstrap/mobile.css')
	]);
	// Both formatted upstream and the minified OpenWrt-installed ui.js are supported.
	const marker = /tabs:\s*baseclass\.singleton\(/.exec(uiSource);
	assert.ok(marker, 'Upstream tabs source not found');
	const objectStart = marker.index + marker[0].length;
	let end = uiSource.indexOf('\n	}),', objectStart);
	if (end >= 0) end += 3;
	else {
		end = uiSource.indexOf('),uploadFile', objectStart);
		assert.ok(end > objectStart, 'Installed LuCI tabs boundary not found');
	}
	const tabs = uiSource.slice(objectStart, end);
	const bootstrap = `
		window.E = function(tag, attrs, children) {
			const node = document.createElement(tag);
			for (const [key, value] of Object.entries(attrs || {})) {
				if (value == null) continue;
				if (typeof value === 'function') node.addEventListener(key, value);
				else node.setAttribute(key, value);
			}
			for (const child of (Array.isArray(children) ? children : [children])) {
				if (child != null) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
			}
			return node;
		};
		String.prototype.format = function(...args) { let i = 0; return this.replace(/%[sd]/g, () => String(args[i++])); };
		window._ = value => value;
		window.L = { bind: (fn, context, ...args) => fn.bind(context, ...args), isObject: v => v && typeof v === 'object' };
		const session = { getLocalData: () => null, setLocalData: (key, value) => value };
		const dom = { isEmpty: node => !node.textContent.trim(), matches: (node, selector) => node.nodeType === 1 && node.matches(selector) };
		function UI() {};
		window.ui = { tabs: (${tabs}), addNotification: (id, node) => document.querySelector('#notifications').append(node) };
		UI.prototype.tabs = ui.tabs;
		window.pollers = [];
		window.poll = { add: callback => pollers.push(callback) };
		window.view = { extend: value => value };
		window.state = { running: false, autostart: false, configure_pending: false, configure_recovery_required: false, update_running: false, client_mode: 'selected', clients: '192.168.1.20/32', destinations: '65.108.59.85/32', lists: 'flowseal', auto_update: false,
			engine_version: 'v1.0.5.2 (mock)', package_version: '0.2.5 (mock)', profile_id: 'alt1', profile: 'hostfakesplit_alt1 / ya.ru / ACK -66000 / tcp_ts_up', table_present: false, queue: 213, integrity_ok: true,
			warnings: ['Только выбранные прямые IPv4 TCP/443. VPN-маршруты не изменяются.'], rule_counters: 'Mock counters' };
		const ids = ['flowseal', 'cloudflare', 'hetzner', 'cloudfront', 'ovh', 'digitalocean'];
		state.list_catalog = ids.map(id => ({ id, title: id === 'flowseal' ? 'Flowseal — Discord / YouTube / сервисы' : id, description: 'Общественный список IPv4-подсетей от itdoginfo; не список доменов' }));
		state.list_state = Object.fromEntries(ids.map((id, i) => [id, { count: [26037, 15, 81, 211, 630, 167][i], updated: 1791971241, sha256: 'a'.repeat(64), error: '' }]));
		window.calls = [];
		window.configureReplies = [];
		window.profilesCatalog = { profiles: ['alt1', 'stock', 'overlap', 'fake', 'fake_split', 'fake_disorder'].map(id => ({ id, title: id, evidence: id === 'alt1' ? 'previously_verified' : 'experimental' })), targets: ['gitlab', 'unitask', 'tavily', 'youtube', 'discord'].map(id => ({ id })), apply_supported: true, limits: { max_rows: 60, max_seconds: 1350 } };
		function protocolCatalog(tcp) {
		 return { groups: [
		  { id: 'tcp', title: 'TCP / HTTPS', description: 'Прямой HTTPS через TCP', profiles: tcp.profiles.map(p => ({ strategy: 'mock strategy', ...p })), targets: tcp.targets.map(t => ({ title: t.id, description: 'Фиксированный ресурс', ...t })), test_supported: true, test_unavailable_reason: '' },
		  { id: 'quic', title: 'QUIC', description: 'Экспериментальный HTTP/3 через UDP/443', profiles: ['quic_google', 'quic_zero', 'quic_google_badsum', 'quic_google_ttl2', 'quic_zero_badsum', 'quic_zero_ttl2'].map(id => ({ id, title: id.replace('quic_', 'Initial · '), evidence: 'experimental', strategy: 'mock QUIC' })), targets: [{ id: 'youtube_h3', title: 'YouTube — изображение HTTP/3', description: 'Не видео' }], test_supported: true, test_unavailable_reason: '' },
		  { id: 'udp', title: 'UDP / голос', description: 'Экспериментальный STUN / Discord', profiles: ['udp_fake2', 'udp_fake6', 'udp_protocol_fake2', 'udp_badsum2', 'udp_ttl2', 'udp_protocol_badsum2'].map(id => ({ id, title: id.replace('udp_', 'STUN · '), evidence: 'experimental', strategy: 'mock UDP' })), targets: [{ id: 'stun_google', title: 'Google STUN', description: 'STUN — не голос' }], test_supported: true, test_unavailable_reason: '' }
		 ] };
		}

		state.protocols = { tcp: { enabled: true, get profile() { return state.profile_id; }, set profile(value) { state.profile_id = value; } }, quic: { enabled: false, profile: 'quic_google' }, udp: { enabled: false, profile: 'udp_fake2' } };
		window.profilesState = { protocol: 'tcp', state: 'idle', running: false, results: [] };
		window.rpc = { declare: spec => async (...args) => {
			calls.push({ method: spec.method, args });
			if (spec.method === 'protocols_catalog') return { ok: true, catalog: structuredClone(protocolCatalog(profilesCatalog)) };
			if (spec.method === 'protocols_status') {
				if (window.profilesStatusError) throw new Error(window.profilesStatusError);
				return { ok: true, catalog: structuredClone(protocolCatalog(profilesCatalog)), data: structuredClone(profilesState) };
			}
			if (spec.method === 'protocols_test') {
				if (window.holdProfilesTest) await new Promise(resolve => { window.releaseProfilesTest = resolve; });
				if (window.profilesTestReply) return structuredClone(window.profilesTestReply);
				Object.assign(profilesState, { protocol: args[0], state: 'pending', running: true, job_id: '123.456', results: [], error: '' });
				return { ok: true, pending: true, job_id: '123.456' };
			}
			if (spec.method === 'status') {
				if (window.statusError) throw new Error(window.statusError);
				if (window.afterApplyStatus) return window.afterApplyStatus();
				return structuredClone(state);
			}
			if (spec.method === 'protocols_apply') {
				if (window.applyProtocolFixture) return window.applyProtocolFixture(args);
				if (window.holdProfilesApply) await new Promise(resolve => { window.releaseProfilesApply = resolve; });
				if (window.profilesApplyReply) return structuredClone(window.profilesApplyReply);
				Object.assign(state.protocols[args[0]], { enabled: args[1], profile: args[2] });
				const job_id = String(Number(state.configure_job_id || 900) + 1);
				Object.assign(state, { configure_pending: false, configure_job_id: job_id, configure_result: { ok: true, job_id } });
				return { ok: true, job_id };
			}
			if (spec.method === 'configure') {
				if (window.holdConfigure) await new Promise(resolve => { window.releaseConfigure = resolve; });
				if (window.configureReply) {
					if (window.configureReply.rolled_back === false) state.running = false;
					configureReplies.push(structuredClone(window.configureReply));
					return structuredClone(window.configureReply);
				}
				const [clients, destinations, autostart, client_mode, lists, auto_update] = args;
				Object.assign(state, { clients, destinations, autostart, client_mode, lists, auto_update });
				const reply = { ok: true, restarted: state.running };
				configureReplies.push(reply);
				return reply;
			}
			if (spec.method === 'control') { state.running = args[0] !== 'stop'; return { ok: true }; }
			if (spec.method === 'logs') return { log: '<img src=x onerror=alert(1)> Mock log' };
			if (spec.method === 'check') return { ok: true, details: 'Mock check; not a bypass test.' };
			if (spec.method === 'update_lists') { state.update_running = true; return { ok: true, pending: true }; }
			throw new Error('Unexpected RPC method');
		} };
		const page = (function() { ${source}\n })();
		page.load().then(data => document.querySelector('#view').append(page.render(data))).catch(error => { window.bootError = String(error); });
	`;
	const html = '<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>zapret2-home — local mock</title><body data-page="local-mock"><div class="container"><p>Локальный mock — не интерфейс роутера</p><div id="notifications"></div><div id="view"></div></div></body></html>';
	let browser;
	let count = 0;
	const ok = (condition, detail) => { assert.ok(condition, detail); count++; };
	const screenshotDir = process.env.SCREENSHOT_DIR || path.join(root, 'dist/protocol-ui-screenshots');
	fs.mkdirSync(screenshotDir, { recursive: true });
	try {
		browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || undefined, headless: true, args: ['--no-sandbox'] });
		const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
		const errors = [];
		page.on('pageerror', error => errors.push(String(error)));
		page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
		await page.route('**/*', route => route.abort()); // No router or external browser requests.
		await page.setContent(html);
		await page.addStyleTag({ content: css + '\n' + mobileCss });
		await page.addScriptTag({ content: bootstrap });
		await page.waitForSelector('#zapret2-save');
		ok(await page.locator('.cbi-tabmenu li').count() === 4, 'Four native tabs');
		ok(await page.locator('[data-tab="settings"][data-tab-title]').getAttribute('data-tab-active') === 'true', 'Settings initially active');
		ok(await page.locator('[data-tab="diagnostics"][data-tab-title]').evaluate(node => node.getBoundingClientRect().height === 0), 'Diagnostics collapsed');
		ok(await page.locator('#zapret2-destinations').evaluate(node => node.getBoundingClientRect().width > 500), 'Wide desktop manual IP field');
		ok(await page.locator('#zapret2-list-choices .cbi-value-description').count() === 0, 'No repeated native description/question icons per list');
		ok(await page.locator('#zapret2-list-choices').evaluate(node => !/Общественный|itdoginfo|Discord|YouTube|Обновл/.test(node.textContent)), 'Compact list choices exclude catalog prose and dates');
		ok(await page.locator('#zapret2-list-label-flowseal').textContent() === 'Flowseal', 'Flowseal title stays compact');
		ok(await page.locator('#zapret2-list-state-flowseal').textContent() === '26 037 сетей', 'Muted grouped subnet count');
		ok(await page.evaluate(() => {
			const stamp = new Date(state.list_state.flowseal.updated * 1000).toLocaleString();
			return document.querySelector('#zapret2-home').textContent.split(stamp).length - 1 === 1;
		}), 'UNIX-second update shown exactly once');
		ok(await page.locator('#zapret2-home').evaluate(node => !/Podkop|VPN/.test(node.textContent)), 'No context-specific routing banners');
		ok(await page.locator('#zapret2-start').isVisible(), 'Stopped service shows Start');
		ok(!await page.locator('#zapret2-stop').isVisible() && !await page.locator('#zapret2-restart').isVisible(), 'Stopped service hides Stop and Restart');
		ok(await page.locator('#zapret2-save').textContent() === 'Сохранить и применить', 'Save-and-apply label');
		await page.screenshot({ path: path.join(screenshotDir, 'settings-desktop.png'), fullPage: true, animations: 'disabled' });
		await page.locator('#zapret2-client-mode').selectOption('all');
		ok(await page.locator('#zapret2-clients').isVisible() === false, 'All mode hides client field');
		await page.locator('#zapret2-destinations').fill('');
		await page.locator('#zapret2-auto-update').check();
		await page.locator('#zapret2-save').click();
		await page.waitForFunction(() => !document.querySelector('#zapret2-save').disabled && document.querySelector('#zapret2-message').textContent === '');
		ok(await page.evaluate(() => JSON.stringify(calls.find(c => c.method === 'configure').args) === JSON.stringify(['', '', false, 'all', 'flowseal', true])), 'All-mode six RPC parameters');
		ok(await page.evaluate(() => !calls.some(c => c.method === 'control')), 'Save never starts service');
		ok(await page.evaluate(() => configureReplies.at(-1).restarted === false && state.running === false), 'Stopped configure does not restart or start service');
		await page.locator('#zapret2-start').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-state').textContent === 'Запущен' && !document.querySelector('#zapret2-save').disabled);
		ok(!await page.locator('#zapret2-start').isVisible(), 'Running service hides Start');
		ok(await page.locator('#zapret2-stop').isVisible() && await page.locator('#zapret2-restart').isVisible(), 'Running service shows Stop and Restart');
		ok(await page.locator('#zapret2-save').isEnabled(), 'Running service allows save');
		ok(await page.locator('#zapret2-message').textContent() === '' && !await page.locator('#zapret2-message').isVisible(), 'No permanent start-success message');
		ok(await page.locator('#zapret2-home').evaluate(node => node.textContent.split('Запущенная служба перезапустится для применения изменений; остановленная не запускается.').length - 1 === 1), 'Single save/restart explanation');
		await page.evaluate(() => { window.activeSaveStart = calls.length; window.holdConfigure = true; });
		await page.locator('#zapret2-save').click();
		await page.waitForFunction(() => typeof window.releaseConfigure === 'function');
		ok(await page.locator('#zapret2-save').isDisabled() && await page.locator('#zapret2-stop').isDisabled(), 'Busy active save disables actions');
		ok((await page.locator('#zapret2-message').textContent()).includes('Выполняется:'), 'Busy operation remains visible');
		await page.evaluate(() => { window.holdConfigure = false; window.releaseConfigure(); });
		await page.waitForFunction(() => !document.querySelector('#zapret2-save').disabled && document.querySelector('#zapret2-message').textContent === '');
		ok(await page.evaluate(() => JSON.stringify(calls.slice(window.activeSaveStart).map(c => c.method)) === JSON.stringify(['configure', 'status'])), 'Active save only calls configure and status, no frontend restart');
		ok(await page.evaluate(() => state.running === true && configureReplies.at(-1).restarted === true), 'Mock backend restarts active service and preserves running state');
		await page.screenshot({ path: path.join(screenshotDir, 'settings-running-desktop.png'), fullPage: true, animations: 'disabled' });
		await page.locator('#zapret2-client-mode').selectOption('selected');
		await page.locator('#zapret2-clients').fill('');
		await page.locator('#zapret2-save').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-message').textContent.includes('Ошибка:'));
		ok(await page.evaluate(() => calls.filter(c => c.method === 'configure').length === 2), 'Empty selected clients rejected');
		await page.locator('#zapret2-clients').fill('192.168.1.33');
		await page.evaluate(async () => { state.list_state.flowseal.count = 456; await pollers[0](); document.querySelector('#notifications').replaceChildren(); });
		ok(await page.locator('#zapret2-clients').inputValue() === '192.168.1.33', 'Polling preserves edits');
		ok((await page.locator('#zapret2-list-state-flowseal').textContent()).includes('456'), 'Polling updates list count');
		for (const rolledBack of [true, false]) {
			await page.evaluate(rolled_back => {
				state.running = true;
				window.configureReply = { ok: false, error: '<img src=x onerror=alert(1)> Mock apply failure', rolled_back };
				window.failureSaveStart = calls.length;
			}, rolledBack);
			await page.evaluate(() => pollers[0]());
			await page.locator('#zapret2-save').click();
			await page.waitForFunction(() => !document.querySelector('#zapret2-save').disabled && document.querySelector('#zapret2-message').textContent.includes('Mock apply failure'));
			ok((await page.locator('#zapret2-message').textContent()).includes(rolledBack ? 'Предыдущие настройки восстановлены' : 'Откат не выполнен'), 'Rollback outcome shown: ' + rolledBack);
			ok(await page.evaluate(() => JSON.stringify(calls.slice(window.failureSaveStart).map(c => c.method)) === JSON.stringify(['status', 'configure', 'status'])), 'Failed apply also reads status: ' + rolledBack);
			ok(await page.locator('#zapret2-message img').count() === 0, 'Apply error remains safe text');
			ok(await page.locator('#zapret2-clients').inputValue() === '192.168.1.33', 'Apply failure preserves edited clients');
		}
		await page.evaluate(() => { window.configureReply = null; window.statusError = 'Mock status unavailable'; return pollers[0](); });
		ok(!await page.locator('#zapret2-start').isVisible() && !await page.locator('#zapret2-stop').isVisible() && !await page.locator('#zapret2-restart').isVisible(), 'Unknown status hides all lifecycle actions');
		ok(await page.locator('#zapret2-save').isDisabled(), 'Unknown status blocks save');
		ok((await page.locator('#zapret2-message').textContent()).includes('Mock status unavailable'), 'Actual status error visible');
		await page.evaluate(() => { window.statusError = ''; return pollers[0](); });
		await page.locator('#zapret2-save').click();
		await page.waitForFunction(() => !document.querySelector('#zapret2-save').disabled && document.querySelector('#zapret2-message').textContent === '');
		await page.locator('.cbi-tabmenu li[data-tab="diagnostics"] a').click();
		ok(await page.locator('[data-tab="diagnostics"][data-tab-title]').getAttribute('data-tab-active') === 'true', 'Native diagnostic tab switches');
		ok(await page.locator('[data-tab="diagnostics"][data-tab-title] .cbi-value').count() === 0, 'Diagnostics are not offset native form rows');
		ok(await page.locator('[data-tab="diagnostics"][data-tab-title] details').evaluateAll(nodes => nodes.length === 3 && nodes.every(node => !node.open)), 'Advanced diagnostics closed by default');
		ok(await page.locator('#zapret2-status-update_error').isVisible() === false, 'Empty update error hidden');
		ok(await page.locator('#zapret2-status-warnings').isVisible() === false, 'Routine backend caveats not repeated');
		ok(await page.locator('#zapret2-diagnostic-summary').evaluate(node => {
			const pane = node.closest('[data-tab-title]');
			const start = pane.getBoundingClientRect().left + parseFloat(getComputedStyle(pane).paddingLeft);
			return Array.from(node.children).filter(row => getComputedStyle(row).display !== 'none').every(row => Math.abs(row.firstElementChild.getBoundingClientRect().left - start) < 1 && getComputedStyle(row.firstElementChild).textAlign === 'left');
		}), 'Desktop diagnostic labels align with parent content start');
		await page.locator('#zapret2-check-button').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-check').textContent.includes('Mock check'));
		ok((await page.locator('#zapret2-check').textContent()).includes('not a bypass test'), 'Diagnostic check output');
		await page.screenshot({ path: path.join(screenshotDir, 'diagnostics-desktop.png'), fullPage: true, animations: 'disabled' });
		await page.locator('.cbi-tabmenu li[data-tab="journal"] a').click();
		await page.locator('#zapret2-log-button').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-log').textContent.includes('Mock log'));
		ok(await page.locator('#zapret2-log img').count() === 0, 'Log injection stays text');
		await page.screenshot({ path: path.join(screenshotDir, 'journal-desktop.png'), fullPage: true, animations: 'disabled' });
		await page.locator('.cbi-tabmenu li[data-tab="settings"] a').click();
		await page.locator('#zapret2-update-lists').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-update-lists').disabled);
		ok(await page.locator('#zapret2-save').isDisabled(), 'Pending list update blocks save');
		ok(await page.evaluate(() => calls.find(c => c.method === 'update_lists').args.length === 0), 'Fixed list-update RPC without arguments');
		await page.evaluate(async () => { state.update_running = false; state.update_error = 'Mock download failure'; await pollers[0](); });
		ok((await page.locator('#zapret2-message').textContent()).includes('Mock download failure'), 'Async list update failure visible');
		await page.locator('.cbi-tabmenu li[data-tab="diagnostics"] a').click();
		ok(await page.locator('#zapret2-status-update_error').isVisible(), 'Real error row shown');
		await page.evaluate(async () => { state.update_error = ''; await pollers[0](); });
		ok(await page.locator('#zapret2-status-update_error').isVisible() === false, 'Recovery hides empty error row');
		await page.locator('.cbi-tabmenu li[data-tab="profiles"] a').click();
		ok(await page.locator('[data-tab="profiles"][data-tab-title]').getAttribute('data-tab-active') === 'true', 'Native Profiles tab switches');
		ok(await page.locator('#zapret2-profiles-start').isEnabled(), 'Practical defaults permit explicit launch');
		ok(await page.locator('#zapret2-protocol-panel input:checked').count() === 5 && await page.evaluate(() => !calls.some(c => c.method === 'protocols_test')), 'Practical defaults do not auto-start');
		ok(await page.locator('#zapret2-test-repeat').inputValue() === '1', 'One repeat default');
		ok(await page.locator('#zapret2-protocol-panel button').count() === 6 && await page.locator('[data-tab="profiles"][data-tab-title] textarea').count() === 0, 'Test all/clear controls and manual apply, no strategy/URL editor');
		ok(await page.locator('#zapret2-active-profile').textContent() === 'Основной · alt1', 'Saved active profile visible');
		ok(await page.locator('#zapret2-apply-profile').inputValue() === 'alt1' && await page.locator('#zapret2-profiles-apply').isDisabled(), 'Selector starts at confirmed saved profile, no-op apply disabled');
		ok(await page.locator('#zapret2-protocol-panel input[type="checkbox"]').count() === 11, 'Six profiles and five targets');
		ok(await page.locator('[data-tab="profiles"][data-tab-title]').evaluate(node => node.textContent.includes('минут') && node.textContent.includes('1350') && node.textContent.split('Реальную голосовую связь проверьте вручную').length === 2), 'Single bounded-resource/video+voice caveat and minutes warning');
		await page.locator('#zapret2-test-profile-alt1').check(); await page.locator('#zapret2-test-profile-stock').check();
		for (const id of ['gitlab', 'unitask', 'tavily']) await page.locator('#zapret2-test-target-' + id).check();
		await page.locator('#zapret2-test-repeat').selectOption('2');
		await page.evaluate(() => { window.holdProfilesTest = true; });
		await page.locator('#zapret2-profiles-start').click();
		await page.waitForFunction(() => typeof window.releaseProfilesTest === 'function');
		ok(await page.locator('#zapret2-profiles-start').isDisabled(), 'In-flight launch blocks duplicate tests');
		ok(await page.locator('#zapret2-profiles-apply').isDisabled(), 'In-flight test launch blocks apply');
		ok((await page.locator('#zapret2-profiles-state').textContent()).includes('Запуск теста') && await page.locator('#zapret2-profiles-progress').getAttribute('value') === null, 'Unacknowledged launch has indeterminate progress');
		await page.evaluate(() => { window.holdProfilesTest = false; window.releaseProfilesTest(); });
		await page.waitForFunction(() => document.querySelector('#zapret2-profiles-state').textContent.includes('результат ещё не подтверждён'));
		ok(await page.evaluate(() => JSON.stringify(calls.find(c => c.method === 'protocols_test').args) === JSON.stringify(['tcp', 'alt1 stock', 'gitlab unitask tavily', 2])), 'Fixed ID strings and integer repeat');
		ok(await page.locator('#zapret2-profiles-start').isDisabled() && await page.locator('#zapret2-test-profile-alt1').isDisabled(), 'Pending job locks test controls');
		ok(await page.locator('#zapret2-profiles-apply').isDisabled(), 'Running test blocks apply');
		ok(await page.locator('#zapret2-profiles-progress').evaluate(n => n.value === 0 && n.max === 12) && (await page.locator('#zapret2-profiles-state').textContent()).includes('0%'), 'Acknowledged pending shows real zero, not completion');
		await page.screenshot({ path: path.join(screenshotDir, 'profiles-pending-desktop.png'), fullPage: true, animations: 'disabled' });
		await page.evaluate(async () => {
			Object.assign(profilesState, { state: 'results', running: true, results: [
				{ protocol: 'tcp', profile: 'alt1', target: 'gitlab', repeat: 1, status: 200, bytes: 42, time_total: 0.4, full_match: true, failure: '' },
				{ protocol: 'tcp', profile: 'stock', target: 'tavily', repeat: 1, status: 0, bytes: 0, time_total: 5, full_match: false, failure: 'connect_or_setup' }
			] }); await pollers[1]();
		});
		ok((await page.locator('#zapret2-profiles-state').textContent()).includes('2/12'), 'Separate profile poll shows progress');
		ok((await page.locator('#zapret2-profiles-technical').textContent()).includes('HTTP 200 · 42 B · 0.4 s · Полная загрузка (full_match)'), 'Compact result metrics');
		ok((await page.locator('#zapret2-profiles-technical').textContent()).includes('connect_or_setup'), 'Connection failure is not cutoff proof');
		ok(await page.locator('#zapret2-profiles-start').isDisabled(), 'Results with cleanup running still block launch');
		await page.locator('.cbi-tabmenu li[data-tab="settings"] a').click();
		ok(await page.locator('#zapret2-save').isEnabled(), 'Profile test does not block unrelated settings');
		await page.locator('#zapret2-save').click(); await page.waitForFunction(() => !document.querySelector('#zapret2-save').disabled);
		ok(await page.evaluate(() => state.profile === 'hostfakesplit_alt1 / ya.ru / ACK -66000 / tcp_ts_up'), 'Active profile stays unchanged');
		await page.locator('.cbi-tabmenu li[data-tab="profiles"] a').click();
		await page.evaluate(async () => { profilesState.state = 'error'; profilesState.error = '<img src=x onerror=alert(1)> Cleanup required'; await pollers[1](); });
		ok((await page.locator('#zapret2-profiles-state').textContent()).includes('Cleanup required') && await page.locator('#zapret2-profiles-state img').count() === 0, 'Cleanup error visible as safe text');
		ok(await page.locator('#zapret2-profiles-start').isDisabled(), 'Cleanup failure running lock retained');
		ok((await page.locator('#zapret2-profiles-state').textContent()).includes('Ошибка теста') && !(await page.locator('#zapret2-profiles-state').textContent()).includes('Тест завершён'), 'Error stage remains error with collected rows');
		await page.evaluate(async () => { window.profilesStatusError = 'Mock profile status unavailable'; await pollers[1](); });
		ok((await page.locator('#zapret2-profiles-state').textContent()).includes('Mock profile status unavailable'), 'Profile status transport failure visible');
		ok(await page.locator('#zapret2-profiles-progress').getAttribute('value') === null && (await page.locator('#zapret2-profiles-state').textContent()).includes('Последние данные: 2/12'), 'Lost status is indeterminate with last known counts');
		ok((await page.locator('#zapret2-profiles-technical').textContent()).includes('full_match'), 'Status failure retains last partial rows');
		ok(await page.locator('#zapret2-profiles-start').isDisabled(), 'Unknown test status blocks new launch');
		await page.evaluate(async () => { window.profilesStatusError = ''; Object.assign(profilesState, { state: 'results', running: false, error: '' }); await pollers[1](); });
		ok(await page.locator('#zapret2-profiles-start').isEnabled(), 'Completed cleanup permits next explicit test');
		await page.screenshot({ path: path.join(screenshotDir, 'profiles-results-desktop.png'), fullPage: true, animations: 'disabled' });
		await page.evaluate(() => { window.profilesTestReply = { ok: false, error: '<script> Mock test rejected' }; });
		await page.locator('#zapret2-profiles-start').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-profiles-state').textContent.includes('Mock test rejected'));
		ok(await page.locator('#zapret2-profiles-state script').count() === 0 && await page.locator('#zapret2-profiles-start').isEnabled(), 'Launch failure recovers via readback without HTML');
		await page.evaluate(() => { window.profilesTestReply = null; });
		for (const kind of ['profile', 'target']) {
			await page.locator('#zapret2-test-' + kind + '-clear').click();
			ok(await page.locator('#zapret2-profiles-start').isDisabled(), 'Clear ' + kind + ' disables test');
			await page.locator('#zapret2-test-' + kind + '-all').click();
		}
		await page.locator('#zapret2-profiles-start').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-profiles-state').textContent.includes('0/60'));
		ok(await page.evaluate(() => JSON.stringify(calls.filter(c => c.method === 'protocols_test').at(-1).args) === JSON.stringify(['tcp', 'alt1 stock overlap fake fake_split fake_disorder', 'gitlab unitask tavily youtube discord', 2])), 'Test ALL sends fixed six/five IDs and repeat 2');
		await page.evaluate(async () => {
			Object.assign(profilesState, { state: 'results', running: false, results: profilesCatalog.profiles.flatMap(profile => profilesCatalog.targets.flatMap(target => [1, 2].map(repeat => ({ protocol: 'tcp', profile: profile.id, target: target.id, repeat, status: 200, bytes: 42, time_total: 0.4, full_match: true, failure: '' })))) });
			await pollers[1]();
		});
		ok((await page.locator('#zapret2-profiles-state').textContent()).includes('60/60'), 'Full sixty-row results accepted');
		ok(await page.evaluate(() => !calls.some(c => c.method === 'protocols_apply') && state.profile_id === 'alt1'), 'Successful tests never auto-apply');
		await page.locator('#zapret2-apply-profile').selectOption('alt1');
		ok(await page.locator('#zapret2-profiles-apply').isDisabled(), 'Same actual profile cannot be applied');
		await page.locator('#zapret2-apply-profile').selectOption('stock');
		ok(await page.locator('#zapret2-active-profile').textContent() === 'Основной · alt1', 'Candidate is not shown as actual active profile');
		for (const field of ['configure_pending', 'configure_recovery_required', 'update_running']) {
			await page.evaluate(async field => { state[field] = true; await pollers[0](); }, field);
			ok(await page.locator('#zapret2-profiles-apply').isDisabled(), 'Apply blocked by ' + field);
			await page.evaluate(async field => { state[field] = false; await pollers[0](); }, field);
		}
		await page.evaluate(async () => { delete state.profile_id; await pollers[0](); });
		ok(await page.locator('#zapret2-profiles-apply').isDisabled() && (await page.locator('#zapret2-active-profile').textContent()).includes('Неизвестен'), 'Absent ID fails closed without false alt1 fallback');
		await page.evaluate(async () => { state.profile_id = 'alt1'; await pollers[0](); window.holdProfilesApply = true; });
		await page.locator('#zapret2-profiles-apply').click();
		await page.waitForFunction(() => typeof window.releaseProfilesApply === 'function');
		ok(await page.locator('#zapret2-profiles-start').isDisabled() && await page.locator('#zapret2-profiles-apply').isDisabled(), 'Apply serializes launch and duplicates');
		await page.evaluate(() => {
			Object.assign(state, { configure_job_id: 901, configure_pending: true });
			window.profilesApplyReply = { ok: true, pending: true, job_id: 901 };
			window.holdProfilesApply = false; window.releaseProfilesApply();
		});
		await page.waitForFunction(() => calls.filter(c => c.method === 'status').length > 0 && document.querySelector('#zapret2-state').textContent.includes('Применяются'));
		ok((await page.locator('#zapret2-message').textContent()).includes('Выполняется'), 'Pending apply is not reported complete');
		ok(await page.locator('#zapret2-active-profile').textContent() === 'Основной · alt1', 'Pending acceptance leaves actual old ID visible');

		await page.evaluate(() => { Object.assign(state, { profile_id: 'stock', configure_pending: false, configure_result: { ok: true, job_id: 901 } }); });
		await page.waitForFunction(() => document.querySelector('#zapret2-message').textContent === '');
		ok(await page.locator('#zapret2-active-profile').textContent() === 'Базовый · stock' && await page.locator('#zapret2-profiles-apply').isDisabled(), 'Matching terminal job and saved ID confirm apply');
		ok(await page.locator('#zapret2-clients').inputValue() === '192.168.1.33', 'Apply preserves unsaved main inputs');
		ok(await page.evaluate(() => JSON.stringify(calls.filter(c => c.method === 'protocols_apply').at(-1).args) === JSON.stringify(['tcp', true, 'stock'])), 'Apply sends exactly one fixed ID');
		await page.locator('#zapret2-apply-profile').selectOption('fake_split');
		await page.evaluate(() => {
			window.profilesApplyReply = { ok: true, job_id: 905 };
			Object.assign(state, { configure_job_id: 905, configure_pending: false, configure_result: { ok: true, job_id: 905 } });
		});
		await page.locator('#zapret2-profiles-apply').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-message').textContent.includes('не подтверждено'));
		ok(await page.locator('#zapret2-active-profile').textContent() === 'Базовый · stock', 'False terminal success cannot relabel active profile');
		await page.evaluate(() => {
			Object.assign(state, { configure_job_id: 902, configure_pending: false, configure_result: { ok: true, job_id: 903 } });
			window.profilesApplyReply = { ok: true, pending: true, job_id: 902 };
		});
		await page.locator('#zapret2-profiles-apply').click();
		await page.waitForFunction(() => document.querySelector('#zapret2-message').textContent.includes('другому заданию'));
		ok(await page.locator('#zapret2-active-profile').textContent() === 'Базовый · stock', 'Mismatched terminal job remains an error');
		for (const rolled_back of [true, false]) {
			await page.evaluate(rolled_back => {
				Object.assign(state, { configure_job_id: 904, configure_pending: false, configure_recovery_required: !rolled_back,
					configure_result: { ok: false, job_id: 904, error: '<img src=x onerror=alert(1)> Profile startup failed', rolled_back } });
				window.profilesApplyReply = { ok: true, pending: true, job_id: 904 };
			}, rolled_back);
			// Backend recovery starts after the request, not before its preflight.
			await page.evaluate(async () => { state.configure_recovery_required = false; await pollers[0](); });
			await page.locator('#zapret2-profiles-apply').click();
			await page.waitForFunction(() => document.querySelector('#zapret2-message').textContent.includes('Profile startup failed'));
			ok((await page.locator('#zapret2-message').textContent()).includes(rolled_back ? 'восстановлены' : 'Откат не выполнен'), 'Profile rollback outcome visible: ' + rolled_back);
			ok(await page.locator('#zapret2-message img').count() === 0 && await page.locator('#zapret2-active-profile').textContent() === 'Базовый · stock', 'Rollback injection safe; old profile truthful');
		}
		await page.evaluate(async () => { state.configure_recovery_required = true; await pollers[0](); });
		ok(await page.locator('#zapret2-profiles-apply').isDisabled(), 'Recovery-required blocks new apply');
		await page.screenshot({ path: path.join(screenshotDir, 'profiles-apply-rollback-desktop.png'), fullPage: true, animations: 'disabled' });
		await page.evaluate(async () => {
			state.configure_recovery_required = false; state.configure_result = null; await pollers[0]();
			window.holdProfilesApply = true; window.releaseProfilesApply = null;
		});
		await page.locator('#zapret2-profiles-apply').click();
		await page.waitForFunction(() => typeof window.releaseProfilesApply === 'function');
		await page.evaluate(() => {
			window.profilesApplyReply = { ok: false, error: 'Apply rejected', rolled_back: true };
			window.statusError = 'Profile readback unavailable'; window.holdProfilesApply = false; window.releaseProfilesApply();
		});
		await page.waitForFunction(() => document.querySelector('#zapret2-message').textContent.includes('Profile readback unavailable'));
		ok((await page.locator('#zapret2-message').textContent()).includes('Apply rejected'), 'Apply failure and failed readback both remain visible');
		ok(await page.locator('#zapret2-profiles-apply').isDisabled() && (await page.locator('#zapret2-active-profile').textContent()).includes('Неизвестен'), 'Failed apply readback invalidates actual active profile and controls');
		for (const width of [390, 320]) {
			const mobile = await browser.newPage({ viewport: { width, height: 844 }, screen: { width, height: 844 }, isMobile: true });
			mobile.on('pageerror', error => errors.push(String(error)));
			mobile.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
			await mobile.route('**/*', route => route.abort());
			await mobile.setContent(html);
			await mobile.addStyleTag({ content: css + '\n' + mobileCss });
			await mobile.addScriptTag({ content: bootstrap });
			await mobile.waitForSelector('#zapret2-save');
			await mobile.screenshot({ path: path.join(screenshotDir, 'settings-mobile-' + width + '.png'), fullPage: true, animations: 'disabled' });
			ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No horizontal overflow at ' + width);
			ok(await mobile.locator('#zapret2-destinations').evaluate(node => node.getBoundingClientRect().width > 200), 'Usable mobile textarea at ' + width);
			await mobile.evaluate(async () => { state.running = true; await pollers[0](); });
			ok(!await mobile.locator('#zapret2-start').isVisible() && await mobile.locator('#zapret2-stop').isVisible() && await mobile.locator('#zapret2-restart').isVisible(), 'Running mobile actions at ' + width);
			ok(await mobile.locator('#zapret2-save').isEnabled(), 'Running mobile save enabled at ' + width);
			ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No running settings overflow at ' + width);
			await mobile.screenshot({ path: path.join(screenshotDir, 'settings-running-mobile-' + width + '.png'), fullPage: true, animations: 'disabled' });
			await mobile.locator('.cbi-tabmenu li[data-tab="diagnostics"] a').click();
			ok(await mobile.locator('#zapret2-diagnostic-summary').evaluate(node => {
				const pane = node.closest('[data-tab-title]');
				const start = pane.getBoundingClientRect().left + parseFloat(getComputedStyle(pane).paddingLeft);
				return Array.from(node.children).filter(row => getComputedStyle(row).display !== 'none').every(row => Math.abs(row.firstElementChild.getBoundingClientRect().left - start) < 1 && getComputedStyle(row.firstElementChild).textAlign === 'left');
			}), 'Mobile diagnostic labels align with parent at ' + width);
			ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No diagnostic overflow at ' + width);
			await mobile.screenshot({ path: path.join(screenshotDir, 'diagnostics-mobile-' + width + '.png'), fullPage: true, animations: 'disabled' });
			await mobile.locator('[data-tab="diagnostics"][data-tab-title] details summary').evaluateAll(nodes => nodes.forEach(node => node.click()));
			ok(await mobile.locator('#zapret2-status-list_details').isVisible(), 'Checksums accessible on demand at ' + width);
			ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No expanded diagnostic overflow at ' + width);
			await mobile.locator('.cbi-tabmenu li[data-tab="profiles"] a').click();
			ok(await mobile.locator('#zapret2-profiles-start').isVisible() && await mobile.locator('#zapret2-profiles-start').isEnabled(), 'Mobile explicit test selections at ' + width);
			ok(await mobile.locator('#zapret2-profiles-apply').isVisible() && await mobile.locator('#zapret2-profiles-apply').isDisabled(), 'Mobile manual apply controls at ' + width);
			await mobile.locator('#zapret2-apply-profile').selectOption('fake_disorder');
			ok(await mobile.locator('#zapret2-profiles-apply').isEnabled(), 'Mobile candidate enables explicit apply at ' + width);
			await mobile.locator('#zapret2-profiles-apply').click();
			await mobile.waitForFunction(() => document.querySelector('#zapret2-active-profile').textContent === 'Ложный + перестановка · fake_disorder');
			ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No manual apply overflow at ' + width);
			await mobile.screenshot({ path: path.join(screenshotDir, 'profiles-selection-mobile-' + width + '.png'), fullPage: true, animations: 'disabled' });
			await mobile.locator('#zapret2-test-profile-alt1').check(); await mobile.locator('#zapret2-test-target-gitlab').check();
			await mobile.locator('#zapret2-profiles-start').click();
			await mobile.waitForFunction(() => document.querySelector('#zapret2-profiles-state').textContent.includes('результат ещё не подтверждён'));
			ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No profile pending overflow at ' + width);
			await mobile.evaluate(async () => { Object.assign(profilesState, { state: 'error', running: true, error: 'Cleanup required ' + 'x'.repeat(200), results: [{ protocol: 'tcp', profile: 'alt1', target: 'gitlab', repeat: 1, status: 200, bytes: 42, time_total: 0.4, full_match: false, failure: 'body' }] }); await pollers[1](); });
			ok(await mobile.locator('#zapret2-profiles-start').isDisabled(), 'Mobile cleanup-error lock at ' + width);
			ok(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No profile results/error overflow at ' + width);

			await mobile.close();
		}
		// Fresh mock-only fixtures keep representative screenshots separate from fault/XSS tests.
		for (const width of [1280, 390, 320]) {
			const fixture = await browser.newPage({ viewport: { width, height: width === 1280 ? 1000 : 844 }, screen: { width, height: 844 }, isMobile: width !== 1280 });
			fixture.on('pageerror', error => errors.push(String(error)));
			fixture.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
			await fixture.route('**/*', route => route.abort());
			await fixture.setContent(html);
			await fixture.addStyleTag({ content: css + '\n' + mobileCss });
			await fixture.addScriptTag({ content: bootstrap });
			await fixture.waitForSelector('#zapret2-save');
			await fixture.locator('.cbi-tabmenu li[data-tab="profiles"] a').click();
			const suffix = width === 1280 ? 'desktop' : 'mobile-' + width;
			ok((await fixture.locator('#zapret2-active-profile').textContent()).includes('Основной'), 'Human-readable saved profile at ' + width);
			ok(await fixture.locator('[data-tab="profiles"] details').evaluateAll(nodes => nodes.every(node => !node.open)), 'Technical evidence collapsed at ' + width);
			ok(await fixture.evaluate(() => !calls.some(c => ['protocols_apply', 'protocols_test'].includes(c.method))), 'No automatic RPC from defaults at ' + width);
			await fixture.screenshot({ path: path.join(screenshotDir, 'profiles-selection-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			for (const kind of ['profile', 'target']) await fixture.locator('#zapret2-test-' + kind + '-all').click();
			await fixture.locator('#zapret2-test-repeat').selectOption('2');
			ok((await fixture.locator('#zapret2-test-plan').textContent()).includes('= 60 проверок'), 'Selection count captures maximum job at ' + width);
			await fixture.locator('#zapret2-profiles-start').click();
			await fixture.waitForFunction(() => document.querySelector('#zapret2-profiles-state').textContent.includes('0/60'));
			await fixture.screenshot({ path: path.join(screenshotDir, 'profiles-pending-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await fixture.evaluate(async () => {
				window.fixtureRows = profilesCatalog.profiles.flatMap(profile => profilesCatalog.targets.flatMap(target => [1, 2].map(repeat => {
					const success = profile.id !== 'fake' && !(profile.id === 'stock' && target.id === 'gitlab' && repeat === 2) && !(profile.id === 'fake_split' && target.id === 'discord');
					return { protocol: 'tcp', profile: profile.id, target: target.id, repeat, status: 200, bytes: success ? 65324 : 100, expected_bytes: 65324,
						time_total: 1.8, full_match: success, failure: success ? '' : 'body', tls_verified: true, route_verified: true, hash_match: success, sha256: 'mock-hash', expected_sha256: 'mock-expected-hash' };
				})));
				Object.assign(profilesState, { state: 'running', running: true, results: fixtureRows.slice(0, 13) }); await pollers[1]();
			});
			ok((await fixture.locator('#zapret2-profiles-state').textContent()).includes('13/60'), 'Actual completed/plan progress at ' + width);
			ok(await fixture.locator('#zapret2-profiles-progress').evaluate(n => n.value === 13 && n.max === 60 && n.getAttribute('aria-describedby') === 'zapret2-profiles-state') && (await fixture.locator('#zapret2-profiles-state').textContent()).includes('21%'), 'Native accessible completed-attempt bar at ' + width);
			ok(await fixture.locator('#zapret2-profiles-progress-panel').evaluate(n => n.getBoundingClientRect().bottom <= document.querySelector('#zapret2-profiles-results').getBoundingClientRect().top), 'Prominent progress is above comparison at ' + width);
			ok(await fixture.evaluate(async () => {
				const bar = document.querySelector('#zapret2-profiles-progress'), live = document.querySelector('#zapret2-profiles-state');
				let mutations = 0; const observer = new MutationObserver(records => { mutations += records.length; }); observer.observe(bar, { attributes: true }); observer.observe(live, { childList: true, characterData: true, subtree: true });
				await pollers[1](); await pollers[1](); const count = mutations + observer.takeRecords().length; observer.disconnect();
				return count === 0 && bar === document.querySelector('#zapret2-profiles-progress');
			}), 'Unchanged poll leaves native bar/live region untouched at ' + width);
			ok(await fixture.locator('#zapret2-result-stock-tavily').getAttribute('data-result') === 'pending', 'Unfinished expected rows not successful at ' + width);
			ok(await fixture.locator('#zapret2-profiles-apply').isDisabled(), 'Progress does not unlock apply at ' + width);
			await fixture.screenshot({ path: path.join(screenshotDir, 'profiles-progress-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await fixture.evaluate(async () => { Object.assign(profilesState, { state: 'results', running: true, results: fixtureRows }); await pollers[1](); });
			ok(await fixture.locator('#zapret2-profiles-progress').evaluate(n => n.value === 60 && n.max === 60) && (await fixture.locator('#zapret2-profiles-state').textContent()).includes('100%') && (await fixture.locator('#zapret2-profiles-state').textContent()).includes('Очистка') && !(await fixture.locator('#zapret2-profiles-state').textContent()).includes('Тест завершён'), '100% checks still means cleanup, not completed job at ' + width);
			ok(await fixture.locator('#zapret2-profiles-apply').isDisabled() && await fixture.locator('#zapret2-profiles-start').isDisabled(), 'Full-check cleanup retains safety lock at ' + width);
			await fixture.screenshot({ path: path.join(screenshotDir, 'profiles-cleanup-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await fixture.evaluate(async () => { profilesState.running = false; await pollers[1](); });
			ok((await fixture.locator('#zapret2-profiles-state').textContent()).includes('Тест завершён') && (await fixture.locator('#zapret2-profiles-state').textContent()).includes('100%'), 'Terminal completion confirmed only after running false at ' + width);
			ok(await fixture.locator('#zapret2-profiles-results tbody tr').count() === 6 && await fixture.locator('#zapret2-profiles-results td').count() === 30, 'Six by five result matrix at ' + width);
			for (const [id, kind, marker] of [['alt1-gitlab', 'success', '✓'], ['stock-gitlab', 'mixed', '±'], ['fake-gitlab', 'failure', '✕']]) {
				ok(await fixture.locator('#zapret2-result-' + id).getAttribute('data-result') === kind && (await fixture.locator('#zapret2-result-' + id).textContent()).includes(marker), 'Distinct text/icon state ' + kind + ' at ' + width);
			}
			ok((await fixture.locator('#zapret2-result-summary-stock').textContent()).includes('Полностью: 4/5'), 'Mixed repeats do not claim full service coverage at ' + width);
			ok(await fixture.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No completed matrix overflow at ' + width);
			ok(await fixture.locator('.z2-service').first().isVisible() === (width !== 1280), 'Desktop matrix / mobile service cards at ' + width);
			ok(await fixture.locator('#zapret2-profiles-results button, #zapret2-profiles-results select, #zapret2-profiles-results input, [id^="zapret2-result-select-"]').count() === 0, 'Comparison has no redundant selection controls at ' + width);
			ok(await fixture.locator('#zapret2-result-summary-alt1').textContent() === 'Полностью: 5/5' && (await fixture.locator('#zapret2-result-summary-stock').textContent()).includes('Смешано: 1'), 'Concise full coverage and explicit mixed coverage at ' + width);
			ok(await fixture.evaluate(() => innerWidth > 700 || document.querySelector('.z2-matrix caption').getBoundingClientRect().width >= document.querySelector('.z2-matrix').getBoundingClientRect().width - 1), 'Mobile job caption uses full card width at ' + width);
			await fixture.screenshot({ path: path.join(screenshotDir, 'profiles-results-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			// Changing future choices must not reinterpret the completed job.
			const resultBefore = await fixture.locator('#zapret2-profiles-results').textContent();
			for (const kind of ['profile', 'target']) await fixture.locator('#zapret2-test-' + kind + '-clear').click();
			ok(await fixture.locator('#zapret2-profiles-results').textContent() === resultBefore && (await fixture.locator('#zapret2-profiles-state').textContent()).includes('60/60'), 'Last-job matrix survives new checkbox selections at ' + width);
			const rpcBefore = await fixture.evaluate(() => calls.length);
			await fixture.locator('#zapret2-result-stock-gitlab').click();
			ok(await fixture.locator('#zapret2-apply-profile').inputValue() === 'alt1' && await fixture.evaluate(before => calls.length === before && !calls.some(c => c.method === 'protocols_apply'), rpcBefore), 'Result cells neither select a profile nor issue hidden RPC at ' + width);
			await fixture.locator('#zapret2-apply-profile').selectOption('stock');
			ok(await fixture.locator('#zapret2-apply-profile').count() === 1 && await fixture.evaluate(before => calls.length === before && !calls.some(c => c.method === 'protocols_apply') && state.profile_id === 'alt1', rpcBefore), 'Only manual selector changes candidate, without writing at ' + width);
			await fixture.locator('#zapret2-protocol-panel details').last().locator('summary').click();
			ok(await fixture.locator('#zapret2-profiles-technical').isVisible() && (await fixture.locator('#zapret2-profiles-technical').textContent()).includes('HTTP 200'), 'Per-attempt metrics available only on demand at ' + width);
			ok(await fixture.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No expanded attempt-detail overflow at ' + width);
			await fixture.locator('#zapret2-protocol-panel details').last().locator('summary').click();
			await fixture.evaluate(() => { window.profilesApplyReply = { ok: false, error: 'Не удалось запустить новый профиль (mock).', rolled_back: true }; });
			await fixture.locator('#zapret2-profiles-apply').click();
			await fixture.waitForFunction(() => document.querySelector('#zapret2-message').textContent.includes('Предыдущие настройки восстановлены'));
			// Production messages stay visible; only redundant mock notification bubbles are cleared for the artifact.
			await fixture.evaluate(() => document.querySelector('#notifications').replaceChildren());
			ok((await fixture.locator('#zapret2-message').textContent()).includes('Не удалось запустить') && (await fixture.locator('#zapret2-active-profile').textContent()).includes('alt1'), 'Honest rollback error with unchanged saved profile at ' + width);
			await fixture.screenshot({ path: path.join(screenshotDir, 'profiles-apply-rollback-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			// Exercise incomplete/missing coverage after saving the clean representative artifacts.
			for (const profile of ['alt1', 'stock']) await fixture.locator('#zapret2-test-profile-' + profile).check();
			await fixture.locator('#zapret2-test-target-gitlab').check();
			await fixture.locator('#zapret2-profiles-start').click();
			await fixture.waitForFunction(() => document.querySelector('#zapret2-profiles-state').textContent.includes('0/4'));
			await fixture.evaluate(async () => { Object.assign(profilesState, { state: 'running', running: true, results: [fixtureRows[0]] }); await pollers[1](); });
			ok(await fixture.locator('#zapret2-result-alt1-gitlab').getAttribute('data-result') === 'partial' && await fixture.locator('#zapret2-result-alt1-youtube').getAttribute('data-result') === 'untested', 'Partial repeated attempts and unselected service remain distinct at ' + width);
			await fixture.evaluate(async () => { Object.assign(profilesState, { state: 'results', running: false, results: [fixtureRows[0], { ...fixtureRows[1], full_match: false, failure: 'body' }] }); await pollers[1](); });
			ok(await fixture.locator('#zapret2-result-alt1-gitlab').getAttribute('data-result') === 'mixed' && await fixture.locator('#zapret2-result-stock-gitlab').getAttribute('data-result') === 'missing' && (await fixture.locator('#zapret2-profiles-state').textContent()).includes('2/4'), 'Missing expected rows and mixed repeats cannot form an all-green result at ' + width);
			ok((await fixture.locator('#zapret2-result-summary-stock').textContent()).includes('Не завершено: 1') && await fixture.locator('#zapret2-profiles-progress').evaluate(n => n.value === 2 && n.max === 4), 'Incomplete terminal plan stays 50%, missing coverage explicit at ' + width);
			await fixture.locator('#zapret2-profiles-start').click();
			await fixture.waitForFunction(() => document.querySelector('#zapret2-profiles-state').textContent.includes('0/4'));
			await fixture.evaluate(async () => { profilesState.state = 'running'; profilesState.results = [fixtureRows[0], fixtureRows[0], { ...fixtureRows[0], profile: 'fake' }]; await pollers[1](); });
			ok(await fixture.locator('#zapret2-profiles-progress').evaluate(n => n.value === 1 && n.max === 4), 'Duplicates and out-of-plan attempts do not inflate progress at ' + width);
			await fixture.evaluate(async () => { profilesState.results[0].time_total = 'bad'; await pollers[1](); });
			ok(await fixture.locator('#zapret2-profiles-progress').getAttribute('value') === null && (await fixture.locator('#zapret2-profiles-state').textContent()).includes('Последние данные: 1/4'), 'Malformed status keeps last counts, not healthy determinate progress at ' + width);
			await fixture.close();
		}

		// Independent protocol controls: native buttons, staged state, strict scoped tests.
		for (const width of [1280, 390, 320]) {
			const protocolPage = await browser.newPage({ viewport: { width, height: width === 1280 ? 1000 : 844 }, isMobile: width !== 1280 });
			protocolPage.on('pageerror', error => errors.push(String(error)));
			protocolPage.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
			await protocolPage.route('**/*', route => route.abort());
			await protocolPage.setContent(html); await protocolPage.addStyleTag({ content: css + '\n' + mobileCss });
			await protocolPage.addScriptTag({ content: bootstrap }); await protocolPage.waitForSelector('#zapret2-save');
			await protocolPage.locator('#zapret2-clients').fill('192.168.1.77');
			await protocolPage.locator('.cbi-tabmenu li[data-tab="profiles"] a').click();
			const suffix = width === 1280 ? 'desktop' : 'mobile-' + width;
			const selectProtocol = async id => protocolPage.locator('#zapret2-protocol-' + id).click();
			const overflow = async label => ok(await protocolPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth), label + ' fits ' + width);
			ok(await protocolPage.locator('#zapret2-protocol-summary > div').count() === 3, 'All saved branches share common summary at ' + width);
			ok(await protocolPage.locator('[id$="branch-enabled"]').count() === 0 && !/ветк/i.test(await protocolPage.locator('[data-tab="profiles"][data-tab-title]').textContent()), 'No separate enable checkbox or branch jargon at ' + width);
			for (const id of ['tcp', 'quic', 'udp']) {
				const prefix = '#zapret2-' + (id === 'tcp' ? '' : id + '-');
				ok(await protocolPage.locator(prefix + 'apply-profile').evaluate(select => select.options.length === 7 && select.options[0].value === '' && select.options[0].textContent === 'Выключено') && await protocolPage.locator(prefix + 'apply-profile').inputValue() === (id === 'tcp' ? 'alt1' : ''), 'Single selector starts at saved ' + id + ' choice: Off plus six IDs at ' + width);
				ok(await protocolPage.locator(prefix + 'profiles-apply').isDisabled() && (await protocolPage.locator(prefix + 'apply-hint').textContent()).includes('уже сохранён'), 'Unchanged ' + id + ' is a no-op, including Off at ' + width);
			}
			await overflow('Simple protocol selection');
			await protocolPage.screenshot({ path: path.join(screenshotDir, 'protocol-selection-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			ok((await protocolPage.locator('#zapret2-summary-quic').textContent()).includes('Выключен') && (await protocolPage.locator('#zapret2-protocol-saved-state').textContent()).includes('остановлена'), 'Saved disabled differs from stopped service at ' + width);
			ok(await protocolPage.locator('[data-tab="profiles"] input, [data-tab="profiles"] select').evaluateAll(inputs => inputs.every(el => el.id && el.labels.length)), 'Every protocol checkbox/select has native accessible label at ' + width);
			ok(await protocolPage.evaluate(() => { const ids = [...document.querySelectorAll('[id]')].map(el => el.id); return new Set(ids).size === ids.length; }), 'Protocol control IDs unique at ' + width);
			await protocolPage.locator('#zapret2-protocol-quic').focus(); await protocolPage.keyboard.press('Enter');
			ok(await protocolPage.locator('#zapret2-protocol-quic').getAttribute('aria-pressed') === 'true' && await protocolPage.locator('#zapret2-quic-protocol-panel').isVisible() && !await protocolPage.locator('#zapret2-protocol-panel').isVisible(), 'Keyboard Enter switches section accessibly at ' + width);
			ok(await protocolPage.locator('#zapret2-protocol-quic').evaluate(el => el === document.activeElement && getComputedStyle(el).outlineStyle !== 'none'), 'Native navigation retains visible keyboard focus at ' + width);
			await protocolPage.keyboard.press('Tab'); ok(await protocolPage.locator('#zapret2-protocol-udp').evaluate(el => el === document.activeElement), 'Keyboard navigation order reaches UDP at ' + width);
			await protocolPage.keyboard.press('Space'); ok(await protocolPage.locator('#zapret2-protocol-udp').getAttribute('aria-pressed') === 'true', 'Space activates native protocol button at ' + width);
			await selectProtocol('quic');
			ok(await protocolPage.locator('#zapret2-quic-profiles-start').isEnabled(), 'Available HTTP3 capability enables explicit test with saved branch OFF at ' + width);
			ok((await protocolPage.locator('#zapret2-quic-protocol-panel').textContent()).includes('НЕ видео') && (await protocolPage.locator('#zapret2-summary-quic').textContent()).includes('Выключен'), 'HTTP3 thumbnail test is separate from video and branch enable state at ' + width);
			await protocolPage.locator('#zapret2-quic-test-profile-clear').click();
			ok(await protocolPage.locator('#zapret2-quic-profiles-start').isDisabled(), 'Empty QUIC choice blocks test at ' + width);
			await protocolPage.locator('#zapret2-quic-test-profile-all').click(); await protocolPage.locator('#zapret2-quic-test-repeat').selectOption('2');
			ok(await protocolPage.locator('#zapret2-quic-protocol-panel .z2-choices-profile input:checked').count() === 6 && (await protocolPage.locator('#zapret2-quic-test-plan').textContent()).includes('= 12 проверок'), 'QUIC select all is six profiles / twelve attempts at ' + width);
			ok(await protocolPage.locator('#zapret2-quic-protocol-panel .z2-choices-profile label').evaluateAll(labels => labels.every(el => el.textContent.includes('экспериментальный') && el.title.includes('не являются отдельными алгоритмами'))), 'QUIC evidence labels describe experimental variants, not six distinct algorithms at ' + width);
			await overflow('HTTP3 enabled six-profile selection');
			await protocolPage.screenshot({ path: path.join(screenshotDir, 'protocol-quic-supported-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await protocolPage.locator('#zapret2-quic-profiles-start').click();
			await protocolPage.waitForFunction(() => document.querySelector('#zapret2-quic-profiles-state').textContent.includes('0/12'));
			ok(await protocolPage.evaluate(() => JSON.stringify(calls.find(c => c.method === 'protocols_test').args) === JSON.stringify(['quic', 'quic_google quic_zero quic_google_badsum quic_google_ttl2 quic_zero_badsum quic_zero_ttl2', 'youtube_h3', 2])), 'HTTP3 launch sends six fixed QUIC IDs and own target at ' + width);
			await protocolPage.evaluate(async () => {
				profilesState.state = 'running'; profilesState.results = [{ protocol: 'quic', profile: 'quic_google', target: 'youtube_h3', repeat: 1, status: 200, bytes: 4096, time_total: 1, full_match: true, failure: '', http_version: '3' }]; await pollers[1]();
			});
			ok(await protocolPage.locator('#zapret2-quic-profiles-progress').evaluate(el => el.value === 1 && el.max === 12), 'HTTP3 counts completed attempts at ' + width);
			await protocolPage.screenshot({ path: path.join(screenshotDir, 'protocol-quic-progress-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await protocolPage.evaluate(async () => {
				profilesState.state = 'results'; profilesState.results = protocolCatalog(profilesCatalog).groups[1].profiles.flatMap(p => [1, 2].map(repeat => ({ protocol: 'quic', profile: p.id, target: 'youtube_h3', repeat, status: 200, bytes: 4096, time_total: 1, full_match: !(p.id === 'quic_zero_ttl2' && repeat === 2), failure: p.id === 'quic_zero_ttl2' && repeat === 2 ? 'body' : '', http_version: '3' }))); await pollers[1]();
			});
			ok((await protocolPage.locator('#zapret2-quic-profiles-state').textContent()).includes('12/12') && (await protocolPage.locator('#zapret2-quic-profiles-state').textContent()).includes('Очистка') && !(await protocolPage.locator('#zapret2-quic-profiles-state').textContent()).includes('Тест завершён') && await protocolPage.locator('#zapret2-quic-profiles-start').isDisabled(), 'HTTP3 full attempt count still waits for cleanup at ' + width);
			await protocolPage.evaluate(async () => { profilesState.running = false; await pollers[1](); });
			ok(await protocolPage.locator('#zapret2-quic-profiles-results tbody tr').count() === 6 && await protocolPage.locator('#zapret2-quic-profiles-results td').count() === 6 && await protocolPage.locator('#zapret2-quic-result-quic_zero_ttl2-youtube_h3').getAttribute('data-result') === 'mixed', 'HTTP3 six-row matrix retains mixed repeated variant at ' + width);
			ok(await protocolPage.locator('#zapret2-quic-profiles-results input, #zapret2-quic-profiles-results select, #zapret2-quic-profiles-results button').count() === 0 && await protocolPage.evaluate(() => !calls.some(c => c.method === 'protocols_apply') && !state.protocols.quic.enabled), 'HTTP3 evidence never auto-applies or auto-enables at ' + width);
			await protocolPage.locator('#zapret2-quic-result-quic_zero_ttl2-youtube_h3').click();
			ok(await protocolPage.locator('#zapret2-quic-apply-profile').inputValue() === '', 'HTTP3 matrix click does not choose a profile at ' + width);
			await overflow('HTTP3 completed six-row matrix');
			await protocolPage.screenshot({ path: path.join(screenshotDir, 'protocol-quic-results-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await protocolPage.locator('#zapret2-quic-apply-profile').selectOption('quic_zero');
			await selectProtocol('udp'); await protocolPage.locator('#zapret2-udp-apply-profile').selectOption('udp_fake6');
			await selectProtocol('quic'); await protocolPage.locator('#zapret2-quic-apply-profile').focus();
			ok(await protocolPage.evaluate(async () => { window.focusedChoice = document.activeElement; await pollers[0](); await pollers[1](); return document.activeElement === focusedChoice && focusedChoice === document.querySelector('#zapret2-quic-apply-profile') && focusedChoice.value === 'quic_zero'; }), 'Main/diagnostic poll preserves focused staged selection at ' + width);
			ok((await protocolPage.locator('#zapret2-summary-quic').textContent()).includes('Выключен') && (await protocolPage.locator('#zapret2-quic-apply-hint').textContent()).includes('Не сохранено'), 'Staged selector never changes saved summary at ' + width);
			ok(await protocolPage.evaluate(() => calls.every(c => ['status', 'protocols_catalog', 'protocols_status', 'protocols_test'].includes(c.method))), 'Only explicit test requested; navigation, selections and polls never apply at ' + width);
			await overflow('QUIC staged selection');
			await protocolPage.locator('#zapret2-quic-profiles-apply').click();
			await protocolPage.waitForFunction(() => document.querySelector('#zapret2-summary-quic').textContent.includes('Включён') && !document.querySelector('#zapret2-save').disabled);
			ok(await protocolPage.evaluate(() => JSON.stringify(calls.find(c => c.method === 'protocols_apply').args) === JSON.stringify(['quic', true, 'quic_zero']) && state.protocols.tcp.enabled && state.profile_id === 'alt1' && !state.protocols.udp.enabled && !state.running), 'Explicit QUIC apply changes only that saved branch, never starts service at ' + width);
			await selectProtocol('udp');
			ok(await protocolPage.locator('#zapret2-udp-apply-profile').inputValue() === 'udp_fake6', 'Other staged branch survives explicit apply/readback at ' + width);
			await protocolPage.locator('#zapret2-udp-test-profile-clear').click();
			ok(await protocolPage.locator('#zapret2-udp-profiles-start').isDisabled(), 'Empty UDP choice blocks test at ' + width);
			await protocolPage.locator('#zapret2-udp-test-profile-all').click();
			await protocolPage.locator('#zapret2-udp-test-repeat').selectOption('2');
			ok(await protocolPage.locator('#zapret2-udp-protocol-panel .z2-choices-profile input:checked').count() === 6 && (await protocolPage.locator('#zapret2-udp-test-plan').textContent()).includes('= 12 проверок'), 'UDP select all is six profiles / twelve attempts at ' + width);
			await protocolPage.locator('#zapret2-udp-profiles-start').click();
			await protocolPage.waitForFunction(() => document.querySelector('#zapret2-udp-profiles-state').textContent.includes('0/12'));
			ok(await protocolPage.evaluate(() => JSON.stringify(calls.find(c => c.method === 'protocols_test' && c.args[0] === 'udp').args) === JSON.stringify(['udp', 'udp_fake2 udp_fake6 udp_protocol_fake2 udp_badsum2 udp_ttl2 udp_protocol_badsum2', 'stun_google', 2])), 'UDP test sends strict own protocol/profile/target/repeat at ' + width);
			await selectProtocol('tcp'); ok(await protocolPage.locator('#zapret2-profiles-apply').isDisabled() && !/udp_fake/.test(await protocolPage.locator('#zapret2-profiles-results').textContent()), 'Running UDP locks other apply without painting TCP rows at ' + width);
			await selectProtocol('udp');
			await protocolPage.evaluate(async () => { profilesState.state = 'running'; profilesState.results = [{ protocol: 'udp', profile: 'udp_fake2', target: 'stun_google', repeat: 1, full_match: true, failure: '' }]; await pollers[1](); });
			ok(await protocolPage.locator('#zapret2-udp-profiles-progress').evaluate(el => el.value === 1 && el.max === 12) && await protocolPage.locator('#zapret2-udp-result-udp_fake2-stun_google').getAttribute('data-result') === 'partial', 'STUN partial repeat has honest progress at ' + width);
			await protocolPage.screenshot({ path: path.join(screenshotDir, 'protocol-udp-progress-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await protocolPage.evaluate(async () => { profilesState.state = 'results'; profilesState.results = protocolCatalog(profilesCatalog).groups[2].profiles.map(p => p.id).flatMap(profile => [1,2].map(repeat => ({ protocol: 'udp', profile, target: 'stun_google', repeat, full_match: !(profile === 'udp_fake6' && repeat === 2), failure: profile === 'udp_fake6' && repeat === 2 ? 'stun_transaction' : '' }))); await pollers[1](); });
			ok(await protocolPage.locator('#zapret2-udp-profiles-apply').isDisabled() && (await protocolPage.locator('#zapret2-udp-profiles-state').textContent()).includes('Очистка'), '100% UDP results still block apply until cleanup at ' + width);
			await protocolPage.evaluate(async () => { profilesState.running = false; await pollers[1](); });
			ok(await protocolPage.locator('#zapret2-udp-result-udp_fake2-stun_google').getAttribute('data-result') === 'success' && await protocolPage.locator('#zapret2-udp-result-udp_fake6-stun_google').getAttribute('data-result') === 'mixed', 'Strict STUN success/mixed repeats stay distinct at ' + width);
			ok((await protocolPage.locator('#zapret2-udp-protocol-panel').textContent()).includes('СТUN') || (await protocolPage.locator('#zapret2-udp-protocol-panel').textContent()).includes('STUN — НЕ голос'), 'STUN never claims automatic voice readiness at ' + width);
			ok(await protocolPage.locator('#zapret2-udp-profiles-results input, #zapret2-udp-profiles-results select, #zapret2-udp-profiles-results button').count() === 0 && (await protocolPage.locator('#zapret2-summary-udp').textContent()).includes('Выключен'), 'Results have no write controls or autoenable at ' + width);
			await protocolPage.locator('#zapret2-udp-result-udp_fake2-stun_google').click();
			ok(await protocolPage.locator('#zapret2-udp-apply-profile').inputValue() === 'udp_fake6', 'Result click cannot replace manual candidate at ' + width);
			await overflow('UDP result cards');
			await protocolPage.screenshot({ path: path.join(screenshotDir, 'protocol-udp-results-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await protocolPage.locator('#zapret2-udp-protocol-panel details').last().locator('summary').click();
			ok((await protocolPage.locator('#zapret2-udp-profiles-technical').textContent()).includes('Строгий STUN-ответ, не голос') && !/undefined|HTTP/.test(await protocolPage.locator('#zapret2-udp-profiles-technical').textContent()), 'UDP metrics may be absent, never fake HTTP/hash proof at ' + width);
			await overflow('Expanded STUN evidence');
			await protocolPage.locator('#zapret2-udp-protocol-panel details').last().locator('summary').click();
			await protocolPage.locator('#zapret2-udp-profiles-apply').click();
			await protocolPage.waitForFunction(() => document.querySelector('#zapret2-summary-udp').textContent.includes('Включён') && !document.querySelector('#zapret2-save').disabled);
			ok(await protocolPage.evaluate(() => state.protocols.tcp.enabled && state.protocols.quic.enabled && state.protocols.udp.enabled && state.protocols.udp.profile === 'udp_fake6'), 'UDP explicit apply preserves TCP and QUIC at ' + width);
			await protocolPage.evaluate(async () => { state.running = true; await pollers[0](); });
			await selectProtocol('tcp'); await protocolPage.locator('#zapret2-apply-profile').selectOption(''); await protocolPage.locator('#zapret2-profiles-apply').click();
			await protocolPage.waitForFunction(() => document.querySelector('#zapret2-summary-tcp').textContent.includes('Выключен') && !document.querySelector('#zapret2-save').disabled);
			ok(await protocolPage.evaluate(() => state.running && state.protocols.quic.enabled && state.protocols.udp.enabled && !calls.some(c => c.method === 'control')), 'Disabling TCP preserves active UDP/QUIC, does not call Stop at ' + width);
			await selectProtocol('quic'); await protocolPage.locator('#zapret2-quic-apply-profile').selectOption(''); await protocolPage.locator('#zapret2-quic-profiles-apply').click();
			await protocolPage.waitForFunction(() => document.querySelector('#zapret2-summary-quic').textContent.includes('Выключен') && !document.querySelector('#zapret2-save').disabled);
			await selectProtocol('udp'); await protocolPage.locator('#zapret2-udp-apply-profile').selectOption('');
			ok(await protocolPage.locator('#zapret2-udp-profiles-apply').isDisabled() && (await protocolPage.locator('#zapret2-udp-apply-hint').textContent()).includes('Остановить всё'), 'Last-branch disable blocked, directs global Stop at ' + width);
			await protocolPage.locator('#zapret2-stop').click(); await protocolPage.waitForFunction(() => document.querySelector('#zapret2-state').textContent === 'Остановлен');
			ok(await protocolPage.evaluate(() => !state.running && state.protocols.udp.enabled && calls.at(-2).method === 'control' && calls.at(-2).args[0] === 'stop'), 'Global Stop halts service, preserves saved branch state at ' + width);
			await protocolPage.locator('#zapret2-udp-apply-profile').selectOption('udp_fake6');
			await protocolPage.evaluate(async () => { state.configure_recovery_required = true; await pollers[0](); });
			for (const id of ['tcp', 'quic', 'udp']) ok(await protocolPage.locator('#zapret2-' + (id === 'tcp' ? '' : id + '-') + 'profiles-apply').isDisabled(), 'Recovery locks ' + id + ' writes at ' + width);
			await protocolPage.evaluate(async () => { state.configure_recovery_required = false; await pollers[0](); });
			ok((await protocolPage.locator('#zapret2-protocol-saved-state').textContent()).includes('остановлена'), 'Summary recovers stopped truth at ' + width);
			// Stale/unknown diagnostics keep last rows but cannot authorize another branch write.
			await protocolPage.locator('#zapret2-udp-apply-profile').selectOption('udp_fake2');
			const writesBeforeFailure = await protocolPage.evaluate(() => calls.filter(c => c.method === 'protocols_apply').length);
			await protocolPage.evaluate(() => { window.profilesStatusError = 'Диагностика недоступна (mock)'; });
			await protocolPage.locator('#zapret2-udp-profiles-apply').click();
			await protocolPage.waitForFunction(() => document.querySelector('#zapret2-message').textContent.includes('Диагностика недоступна'));
			ok(await protocolPage.evaluate(before => calls.filter(c => c.method === 'protocols_apply').length === before, writesBeforeFailure), 'Unknown diagnostic preflight prevents write at ' + width);
			ok(await protocolPage.locator('#zapret2-udp-profiles-progress').getAttribute('value') === null && (await protocolPage.locator('#zapret2-udp-profiles-state').textContent()).includes('Последние данные: 12/12'), 'Stale STUN rows keep last counts, not current determinate success at ' + width);
			for (const id of ['tcp', 'quic', 'udp']) ok(await protocolPage.locator('#zapret2-' + (id === 'tcp' ? '' : id + '-') + 'profiles-apply').isDisabled(), 'Unknown diagnostic locks ' + id + ' writes at ' + width);
			await overflow('Unknown diagnostic state');
			await protocolPage.screenshot({ path: path.join(screenshotDir, 'protocol-udp-stale-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await protocolPage.evaluate(async () => { delete window.profilesStatusError; await pollers[1](); window.statusError = 'Основной статус недоступен (mock)'; await pollers[0](); });
			ok((await protocolPage.locator('#zapret2-protocol-saved-state').textContent()).includes('неизвестен') && (await protocolPage.locator('#zapret2-summary-udp').textContent()).includes('Неизвестно'), 'Main status failure never presents cached settings as confirmed at ' + width);
			ok(await protocolPage.locator('#zapret2-udp-apply-profile').inputValue() === 'udp_fake2', 'Unknown main status retains staged candidate at ' + width);
			await protocolPage.evaluate(() => document.querySelector('#notifications').replaceChildren());
			await protocolPage.screenshot({ path: path.join(screenshotDir, 'protocol-status-unknown-' + suffix + '.png'), fullPage: true, animations: 'disabled' });
			await protocolPage.evaluate(async () => { delete window.statusError; await pollers[0](); });
			await protocolPage.locator('.cbi-tabmenu li[data-tab="settings"] a').click();
			ok(await protocolPage.locator('#zapret2-clients').inputValue() === '192.168.1.77', 'All protocol operations preserve unsaved main form at ' + width);
			await protocolPage.evaluate(async () => {
				for (const id of ['tcp', 'quic', 'udp']) state.protocols[id].enabled = true;
				await pollers[0]();
			});
			await protocolPage.locator('.cbi-tabmenu li[data-tab="profiles"] a').click();
			for (const id of ['tcp', 'quic', 'udp']) {
				await selectProtocol(id);
				const prefix = '#zapret2-' + (id === 'tcp' ? '' : id + '-');
				const saved = await protocolPage.evaluate(id => state.protocols[id].profile, id);
				await protocolPage.locator(prefix + 'apply-profile').selectOption('');
				await protocolPage.locator(prefix + 'apply-profile').focus();
				ok(await protocolPage.evaluate(async prefix => { const select = document.querySelector(prefix + 'apply-profile'); await pollers[0](); await pollers[1](); return select === document.activeElement && select.value === ''; }, prefix), 'Off remains staged and focused through polls at ' + width + '/' + id);
				await selectProtocol(id === 'tcp' ? 'quic' : 'tcp'); await selectProtocol(id);
				await protocolPage.locator(prefix + 'profiles-apply').click();
				await protocolPage.waitForFunction(id => !state.protocols[id].enabled && !document.querySelector('#zapret2-save').disabled, id);
				ok(await protocolPage.evaluate(({ id, saved }) => JSON.stringify(calls.filter(c => c.method === 'protocols_apply').at(-1).args) === JSON.stringify([id, false, saved]) && state.protocols[id].profile === saved && ['tcp', 'quic', 'udp'].filter(other => other !== id).every(other => state.protocols[other].enabled), { id, saved }), 'Off retains exact ID and other enabled protocols at ' + width + '/' + id);
				ok(await protocolPage.locator(prefix + 'profiles-apply').isDisabled() && await protocolPage.locator(prefix + 'active-profile').textContent() === 'Выключено', 'Saved Off is a no-op, not a running profile at ' + width + '/' + id);
				await protocolPage.locator(prefix + 'apply-profile').selectOption(saved);
				await protocolPage.locator(prefix + 'profiles-apply').click();
				await protocolPage.waitForFunction(id => state.protocols[id].enabled && !document.querySelector('#zapret2-save').disabled, id);
				ok(await protocolPage.evaluate(({ id, saved }) => JSON.stringify(calls.filter(c => c.method === 'protocols_apply').at(-1).args) === JSON.stringify([id, true, saved]), { id, saved }), 'Selecting retained profile explicitly enables at ' + width + '/' + id);
			}
			await selectProtocol('udp');
			for (const pending of [false, true]) for (const fault of ['none', 'postcommit-update', 'job', 'result', 'failed', 'missing', 'pending', 'recovery', 'missing-recovery', 'enabled', 'profile', 'lost', 'malformed', 'no-ack']) {
				await protocolPage.evaluate(async ({ pending, fault }) => {
					window.afterApplyStatus = null;
					Object.assign(state, { configure_pending: false, configure_recovery_required: false, update_running: false, configure_result: null });
					state.protocols.udp = { enabled: false, profile: 'udp_fake2' };
					await pollers[0]();
					window.applyProtocolFixture = args => {
						Object.assign(state.protocols[args[0]], { enabled: args[1], profile: args[2] });
						Object.assign(state, { configure_job_id: '21326', configure_pending: false, configure_result: { ok: true, job_id: '21326' } });
						let reads = 0;
						window.afterApplyStatus = () => {
							if (++reads === (pending ? 2 : 1)) {
								if (fault === 'lost') throw new Error('Final readback unavailable');
								if (fault === 'malformed') return { ...state, running: 'false' };
								if (fault === 'postcommit-update') state.update_running = true;
								if (fault === 'job') state.configure_job_id = '21327';
								if (fault === 'result') state.configure_result.job_id = '21327';
								if (fault === 'failed') state.configure_result.ok = false;
								if (fault === 'missing') state.configure_result = null;
								if (fault === 'pending') state.configure_pending = true;
								if (fault === 'recovery') state.configure_recovery_required = true;
								if (fault === 'missing-recovery') delete state.configure_recovery_required;
								if (fault === 'enabled') state.protocols.udp.enabled = false;
								if (fault === 'profile') state.protocols.udp.profile = 'udp_fake2';
							}
							return structuredClone(state);
						};
						return fault === 'no-ack' ? { ok: true } : { ok: true, pending, job_id: '21326' };
					};
				}, { pending, fault });
				await protocolPage.locator('#zapret2-udp-apply-profile').selectOption('udp_fake6');
				const before = await protocolPage.evaluate(() => calls.filter(c => c.method === 'protocols_apply').length);
				await protocolPage.locator('#zapret2-udp-profiles-apply').click();
				await protocolPage.waitForFunction(before => calls.filter(c => c.method === 'protocols_apply').length === before + 1 && !document.querySelector('#zapret2-message').textContent.includes('Выполняется'), before);
				const message = await protocolPage.locator('#zapret2-message').textContent();
				ok(fault === 'none' || fault === 'postcommit-update' ? message === '' : message.includes('Ошибка'), 'Exact final job/status confirmation: pending=' + pending + ', ' + fault + ' at ' + width + ': ' + message);
				if (fault === 'postcommit-update') ok(await protocolPage.locator('#zapret2-udp-profiles-apply').isDisabled() && await protocolPage.evaluate(() => state.update_running), 'Post-commit updater does not falsify success but still blocks new writes at ' + width);
			}
			for (const key of ['configure_pending', 'configure_recovery_required', 'update_running']) {
				await protocolPage.evaluate(async key => {
					window.afterApplyStatus = null;
					Object.assign(state, { configure_pending: false, configure_recovery_required: false, update_running: false });
					delete state[key]; await pollers[0]();
				}, key);
				ok(await protocolPage.locator('button[id$="profiles-apply"]:disabled').count() === 3 && await protocolPage.locator('button[id$="profiles-start"]:disabled').count() === 3, 'Missing lifecycle ' + key + ' fails closed for all protocol writes at ' + width);
				ok((await protocolPage.locator('#zapret2-udp-apply-hint').textContent()).includes('неизвестен') && await protocolPage.locator('#zapret2-udp-apply-profile').inputValue() === 'udp_fake6', 'Missing lifecycle is explained without losing staged selector at ' + width);
			}
			await overflow('Apply readback failure');
			await protocolPage.close();
		}

		for (const width of [1280, 390, 320]) for (const fault of ['unsupported', 'missing', 'corrupt-capability', 'corrupt-status']) {
			const faultPage = await browser.newPage({ viewport: { width, height: 1100 } });
			faultPage.on('pageerror', error => errors.push(String(error)));
			faultPage.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
			await faultPage.route('**/*', route => route.abort());
			const faultSetup = fault === 'missing' ? "const originalRPC = rpc.declare; rpc.declare = spec => spec.method === 'protocols_catalog' || spec.method === 'protocols_status' ? async () => { calls.push({ method: spec.method, args: [] }); throw new Error('Метод protocols_catalog отсутствует: обновите пакет и ACL LuCI.'); } : originalRPC(spec);" : fault === 'corrupt-status' ? "profilesState.protocol = 'quic'; profilesState.state = 'results'; profilesState.results = [{ protocol: 'quic', profile: 'quic_unknown', target: 'youtube_h3', repeat: 1, full_match: true, failure: '', status: 200, bytes: 4096, time_total: 1 }];" : "const originalCatalog = protocolCatalog; protocolCatalog = tcp => { const catalog = originalCatalog(tcp); Object.assign(catalog.groups[1], " + (fault === 'unsupported' ? "{ test_supported: false, test_unavailable_reason: 'Тест недоступен: curl не поддерживает HTTP3.' }" : "{ test_supported: 'true', test_unavailable_reason: '' }") + "); return catalog; };";
			await faultPage.setContent(html); await faultPage.addStyleTag({ content: css + '\n' + mobileCss });
			await faultPage.addScriptTag({ content: bootstrap.replace('const page = (function()', faultSetup + 'const page = (function()') });
			await faultPage.waitForSelector('#zapret2-home'); await faultPage.locator('[data-tab="profiles"] a').click(); await faultPage.locator('#zapret2-protocol-quic').click();
			ok(await faultPage.locator('#zapret2-quic-profiles-start').isDisabled(), 'QUIC test fails closed for ' + fault + ' at ' + width);
			if (fault === 'unsupported') {
				ok((await faultPage.locator('#zapret2-quic-test-hint').textContent()).includes('curl не поддерживает HTTP3') && (await faultPage.locator('#zapret2-quic-profiles-results').textContent()).includes('Автоматический тест недоступен'), 'Unsupported capability retains real reason rather than normal empty-results prompt at ' + width);
				await faultPage.locator('#zapret2-quic-apply-profile').selectOption('quic_zero_ttl2');
				ok(await faultPage.locator('#zapret2-quic-profiles-apply').isEnabled(), 'Unsupported testing does not prohibit explicit experimental branch apply at ' + width);
				await faultPage.locator('#zapret2-protocol-udp').click(); ok(await faultPage.locator('#zapret2-udp-profiles-start').isEnabled(), 'QUIC-only unavailable capability does not hide UDP testing at ' + width); await faultPage.locator('#zapret2-protocol-quic').click();
			} else {
				ok(/Ошибка|некоррект|Некоррект|отсутствует/.test(await faultPage.locator('#zapret2-quic-profiles-state').textContent()) && await faultPage.locator('#zapret2-quic-profiles-apply').isDisabled(), 'Missing/corrupt capability or results stay visible and block unsafe apply at ' + width);
				for (const protocol of ['tcp', 'udp']) {
					await faultPage.locator('#zapret2-protocol-' + protocol).click();
					ok(await faultPage.locator(protocol === 'tcp' ? '#zapret2-profiles-start' : '#zapret2-udp-profiles-start').isDisabled(), 'Unknown capability/status locks ' + protocol + ' at ' + width);
				}
				await faultPage.locator('#zapret2-protocol-quic').click();
			}
			await faultPage.locator('#zapret2-quic-profiles-start').evaluate(el => el.click());
			ok(await faultPage.evaluate(() => !calls.some(c => c.method === 'protocols_test' || c.method === 'protocols_apply')), 'Fail-closed controls never send test/apply for ' + fault + ' at ' + width);
			ok(await faultPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Capability/error state remains contained at ' + width);
			await faultPage.screenshot({ path: path.join(screenshotDir, 'protocol-quic-' + fault + '-' + (width === 1280 ? 'desktop' : 'mobile-' + width) + '.png'), fullPage: true, animations: 'disabled' });
			await faultPage.close();
		}
		const history = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
		history.on('pageerror', error => errors.push(String(error)));
		history.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
		await history.route('**/*', route => route.abort());
		await history.setContent(html); await history.addStyleTag({ content: css + '\n' + mobileCss });
		const historyState = { protocol: 'tcp', state: 'results', running: false, job_id: '123.456', results: [{ protocol: 'tcp', profile: 'alt1', target: 'gitlab', repeat: 1, full_match: true, failure: '', status: 200, bytes: 4096, time_total: 1 }] };
		await history.addScriptTag({ content: bootstrap.replace("window.profilesState = { protocol: 'tcp', state: 'idle', running: false, results: [] };", 'window.profilesState = ' + JSON.stringify(historyState) + ';') });
		await history.waitForSelector('#zapret2-profiles-start'); await history.locator('.cbi-tabmenu a').filter({ hasText: 'Профили' }).click();
		ok(await history.locator('#zapret2-profiles-progress').getAttribute('value') === null && (await history.locator('#zapret2-profiles-state').textContent()).includes('план запуска неизвестен') && !/\d+\/\d+|%/.test(await history.locator('#zapret2-profiles-state').textContent()), 'Loaded history has indeterminate progress without invented attempt denominator');
		ok(await history.locator('#zapret2-profiles-results [data-result="success"]').count() === 0 && await history.locator('#zapret2-apply-profile').inputValue() === 'alt1', 'History does not claim full coverage or choose winner');
		await history.close();
		ok(errors.length === 0, 'No browser JS exceptions or console errors: ' + errors.join('\n'));
		console.log(JSON.stringify({ ok: true, checks: count, js_errors: errors.length, screenshots: screenshotDir, renderer: 'Chrome + upstream LuCI tabs/Bootstrap CSS', target: 'in-memory local mock only; browser network blocked' }, null, 2));
	} finally {
		if (browser) await browser.close();
	}
}
main().catch(error => { console.error(error); process.exitCode = 1; });
