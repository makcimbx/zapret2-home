'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const root = path.resolve(__dirname, '..');
const source = path.join(root, 'files/www/luci-static/resources/view/services/zapret2home.js');

class Element {
	constructor(tag, attrs, children) {
		this.tag = tag;
		this.attrs = attrs || {};
		this.children = [];
		this.disabled = false;
		this.checked = false;
		this.style = {};
		this.hidden = false;
		this.parentNode = null;
		this.value = this.attrs.value || '';
		this.textContent = '';
		this.append(children);
	}
	append(children) {
		if (children == null) return;
		for (const child of Array.isArray(children) ? children : [children]) {
			if (child instanceof Element) { child.parentNode = this; this.children.push(child); }
			else this.children.push(String(child));
		}
	}
	appendChild(child) { this.append(child); return child; }
	setAttribute(key, value) { this.attrs[key] = String(value); }
	focus() { this.focused = true; }
	removeAttribute(key) { delete this.attrs[key]; if (key === 'value') this.value = ''; }
	set textContent(value) { this._text = value; this.children = []; }
	get textContent() { return this._text || ''; }
	set innerHTML(value) { throw new Error('Unsafe innerHTML: ' + value); }
	get innerHTML() { throw new Error('Unsafe innerHTML read'); }
}
function nodes(node) {
	return [node, ...node.children.filter(c => c instanceof Element).flatMap(nodes)];
}
function text(node) {
	return node.textContent + node.children.map(c => c instanceof Element ? text(c) : c).join(' ');
}
const injected = '<img src=x onerror=alert(1)><script>alert(2)</script>';
const profileIds = ['alt1', 'stock', 'overlap', 'fake', 'fake_split', 'fake_disorder'];
const targetIds = ['gitlab', 'unitask', 'tavily', 'youtube', 'discord'];
const profilesCatalog = { profiles: profileIds.map(id => ({ id, title: id, evidence: id === 'alt1' ? 'previously_verified' : 'experimental' })), targets: targetIds.map(id => ({ id })), apply_supported: true, limits: { max_rows: 60, max_seconds: 1350 } };
function protocolCatalog(tcp) {
 return { groups: [
  { id: 'tcp', title: 'TCP / HTTPS', description: 'Прямой HTTPS через TCP', profiles: tcp.profiles.map(p => ({ strategy: 'mock strategy', ...p })), targets: tcp.targets.map(t => ({ title: t.id, description: 'Фиксированный ресурс', ...t })), test_supported: true, test_unavailable_reason: '' },
  { id: 'quic', title: 'QUIC', description: 'Экспериментальный HTTP/3 через UDP/443', profiles: ['quic_google', 'quic_zero', 'quic_google_badsum', 'quic_google_ttl2', 'quic_zero_badsum', 'quic_zero_ttl2'].map(id => ({ id, title: id.replace('quic_', 'Initial · '), evidence: 'experimental', strategy: 'mock QUIC' })), targets: [{ id: 'youtube_h3', title: 'YouTube — изображение HTTP/3', description: 'Не видео' }], test_supported: true, test_unavailable_reason: '' },
  { id: 'udp', title: 'UDP / голос', description: 'Экспериментальный STUN / Discord', profiles: ['udp_fake2', 'udp_fake6', 'udp_protocol_fake2', 'udp_badsum2', 'udp_ttl2', 'udp_protocol_badsum2'].map(id => ({ id, title: id.replace('udp_', 'STUN · '), evidence: 'experimental', strategy: 'mock UDP' })), targets: [{ id: 'stun_google', title: 'Google STUN', description: 'STUN — не голос' }], test_supported: true, test_unavailable_reason: '' }
 ] };
}
const mainCalls = h => h.calls.filter(c => !c.method.startsWith('protocols_'));
function harness(overrides = {}) {
	const state = {
		running: false, autostart: false, configure_pending: false, configure_recovery_required: false, update_running: false, engine_version: 'engine-test', package_version: '1.0',
		profile: 'direct-tls', profile_id: 'alt1', clients: '192.168.1.20/32',
		destinations: '65.108.59.85/32 107.175.71.2/32 52.85.154.99/32',
		table_present: false, queue: 200, warnings: [], rule_counters: '', log: '', integrity_ok: true
	};
	state.protocols = { tcp: { enabled: true, get profile() { return state.profile_id; }, set profile(value) { state.profile_id = value; } }, quic: { enabled: false, profile: 'quic_google' }, udp: { enabled: false, profile: 'udp_fake2' } };
	const profilesState = { protocol: 'tcp', state: 'idle', running: false, results: [] };
	const calls = [];
	const declarations = [];
	const pollers = [];
	const notices = [];
	const tabGroups = [];
	const handlers = {
		status: () => ({ ...state }), configure: (clients, destinations, autostart, client_mode, lists, auto_update) => {
			Object.assign(state, { clients, destinations, autostart, client_mode, lists, auto_update });
			return { ok: true, restarted: state.running };
		},
		control: action => { state.running = action !== 'stop'; return { ok: true }; }, logs: () => ({ log: injected }),
		check: () => ({ ok: true, details: injected }), update_lists: () => ({ ok: true, pending: true }),
		protocols_catalog: () => ({ ok: true, catalog: protocolCatalog(profilesCatalog) }),
		protocols_status: () => ({ ok: true, catalog: protocolCatalog(profilesCatalog), data: structuredClone(profilesState) }),
		protocols_apply: (protocol, enabled, profile) => {
			Object.assign(state.protocols[protocol], { enabled, profile });
			const job_id = String(Number(state.configure_job_id || 900) + 1);
			Object.assign(state, { configure_pending: false, configure_job_id: job_id, configure_result: { ok: true, job_id } });
			return { ok: true, job_id };
		},
		protocols_test: protocol => { Object.assign(profilesState, { protocol, state: 'pending', running: true, job_id: '123.456' }); return { ok: true, pending: true, job_id: '123.456' }; }, ...overrides
	};
	const rpc = { declare(spec) {
		declarations.push(spec);
		return (...args) => {
			calls.push({ method: spec.method, args });
			return Promise.resolve().then(() => handlers[spec.method](...args));
		};
	} };
	const content = fs.readFileSync(source, 'utf8');
	const page = vm.runInNewContext('(function() {\n' + content + '\n})()', {
		view: { extend: value => value }, rpc,
		ui: { addNotification: (...args) => notices.push(args), tabs: { initTabGroup: panes => tabGroups.push(panes) } },
		poll: { add: (callback, seconds) => pollers.push({ callback, seconds }) },
		E: (tag, attrs, children) => new Element(tag, attrs, children),
		_: value => value, console, setTimeout
	}, { filename: source });
	async function render() {
		const tree = page.render(await page.load());
		const all = nodes(tree);
		const get = id => nodes(tree).find(node => node.attrs.id === id);
		const button = label => all.find(node => node.tag === 'button' && text(node) === label);
		return { tree, all, get, button };
	}
	return { state, profilesState, page, render, calls, declarations, pollers, notices, handlers, tabGroups };
}

test('pending configure waits for the matching terminal job instead of claiming acceptance is success', async () => {
	const h = harness(); h.state.running = true;
	let reads = 0;
	h.handlers.configure = () => {
		h.state.configure_job_id = '777'; h.state.configure_pending = true;
		return { ok: true, pending: true, job_id: 777 };
	};
	h.handlers.status = () => {
		if (h.state.configure_pending && ++reads === 2) {
			h.state.configure_pending = false;
			h.state.configure_result = { ok: true, job_id: 777 };
		}
		return { ...h.state };
	};
	const v = await h.render();
	const saving = v.get('zapret2-save').attrs.click();
	await new Promise(resolve => setTimeout(resolve, 20));
	assert.equal(v.get('zapret2-save').disabled, true);
	assert.equal(v.get('zapret2-start').hidden, true);
	assert.equal(v.get('zapret2-stop').hidden, true);
	await saving;
	assert.equal(v.get('zapret2-save').disabled, false);
	assert.equal(text(v.get('zapret2-message')), '');
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 1);
	assert.ok(!h.calls.some(c => c.method === 'control'));
});

test('pending configure rollback and recovery-required states remain errors and block unsafe actions', async () => {
	const h = harness(); h.state.running = true;
	h.handlers.configure = () => {
		Object.assign(h.state, { configure_job_id: 778, configure_pending: false,
			configure_result: { ok: false, job_id: 778, error: 'Apply failed', rolled_back: true } });
		return { ok: true, pending: true, job_id: 778 };
	};
	const v = await h.render();
	await v.get('zapret2-save').attrs.click();
	assert.match(text(v.get('zapret2-message')), /Apply failed/);
	assert.match(text(v.get('zapret2-message')), /восстановлен/i);
	h.state.configure_recovery_required = true;
	await h.pollers[0].callback();
	assert.equal(v.get('zapret2-save').disabled, true);
	assert.equal(v.get('zapret2-stop').hidden, true);
});

test('native view renders safe state, defaults and status-only 5s polling without clobbering edits', async () => {
	const h = harness();
	const v = await h.render();
	assert.equal(h.pollers.length, 2);
	assert.equal(h.pollers[1].seconds, 1);
	assert.equal(h.pollers[0].seconds, 5);
	assert.match(text(v.tree), /IPv4/);
	assert.match(text(v.tree), /LAN/);
	assert.match(text(v.tree), /HTTP\/3/);
	assert.match(text(v.tree), /Остановлен/);
	assert.equal(v.get('zapret2-clients').value, h.state.clients);
	v.get('zapret2-clients').value = '192.168.1.50/32';
	h.state.running = true;
	h.state.autostart = true;
	h.state.profile = injected;
	h.state.warnings = [injected];
	await h.pollers[0].callback();
	assert.equal(v.get('zapret2-clients').value, '192.168.1.50/32');
	assert.equal(v.get('zapret2-autostart').checked, false);
	assert.match(text(v.tree), /Запущен/);
	assert.ok(text(v.tree).includes(injected));
	assert.ok(!v.all.some(n => n.tag === 'img' || n.tag === 'script'));
	assert.ok(mainCalls(h).every(c => c.method === 'status'));
	assert.match(fs.readFileSync(source, 'utf8'), /'require view'/);
	assert.doesNotMatch(fs.readFileSync(source, 'utf8'), /innerHTML/);
	for (const declaration of h.declarations) {
		assert.equal(declaration.object, 'zapret2_home');
		assert.deepEqual(Object.keys(declaration.expect), []);
	}
});

test('configure normalizes valid lists and saves autostart without starting', async () => {
	const h = harness();
	const v = await h.render();
	v.get('zapret2-clients').value = '192.168.1.20/32,\n192.168.1.21';
	v.get('zapret2-destinations').value = '65.108.59.85/32, 52.85.154.99/32';
	v.get('zapret2-autostart').checked = true;
	await v.button('Сохранить и применить').attrs.click();
	const call = h.calls.find(c => c.method === 'configure');
	assert.deepEqual(call.args, ['192.168.1.20/32 192.168.1.21', '65.108.59.85/32 52.85.154.99/32', true, 'selected', '', false]);
	assert.ok(!h.calls.some(c => c.method === 'control'));
	assert.equal(text(v.get('zapret2-message')), '');
	assert.ok(v.all.filter(n => n.tag === 'button' && !n.hidden && !/profiles-(start|apply)$/.test(n.attrs.id)).every(n => !n.disabled));
});

test('invalid IPv4/CIDR, empty and excessive lists never invoke configure', async () => {
	const h = harness();
	const v = await h.render();
	for (const invalid of ['', '::1', '1.2.3.256', '1.2.3.4/33', '1.2.3.4/-1', '1.2.3', '01.2.3.4', '1.2.3.4;reboot', Array(17).fill('1.2.3.4').join(' ')]) {
		v.get('zapret2-clients').value = invalid;
		await v.button('Сохранить и применить').attrs.click();
		assert.match(text(v.get('zapret2-message')), /Ошибка/);
	}
	v.get('zapret2-clients').value = '1.2.3.4/0';
	v.get('zapret2-destinations').value = Array(65).fill('1.2.3.4').join(',');
	await v.button('Сохранить и применить').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 0);
	v.get('zapret2-clients').value = Array(16).fill('1.2.3.4/32').join(' ');
	v.get('zapret2-destinations').value = Array(64).fill('1.2.3.4').join(' ');
	await v.button('Сохранить и применить').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 1);
});

test('fixed controls, check and logs execute and render untrusted text safely', async () => {
	const h = harness();
	const v = await h.render();
	for (const [label, action] of [['Запустить', 'start'], ['Перезапустить', 'restart'], ['Остановить всё', 'stop']]) {
		await v.button(label).attrs.click();
		assert.equal(h.calls.filter(c => c.method === 'control').at(-1).args[0], action);
	}
	await v.button('Проверить').attrs.click();
	assert.ok(text(v.get('zapret2-check')).includes(injected));
	await v.button('Показать журнал').attrs.click();
	assert.ok(text(v.get('zapret2-log')).includes(injected));
});

test('busy actions are disabled, repeated calls and polling are suppressed until completion', async () => {
	let release;
	const h = harness({ control: () => new Promise(resolve => { release = resolve; }) });
	const v = await h.render();
	const promise = v.button('Запустить').attrs.click();
	assert.ok(v.all.filter(n => ['button', 'textarea', 'input'].includes(n.tag) && !/^zapret2-protocol-(tcp|quic|udp)$/.test(n.attrs.id)).every(n => n.disabled));
	await v.button('Остановить всё').attrs.click();
	await h.pollers[0].callback();
	assert.equal(h.calls.filter(c => c.method === 'control').length, 1);
	assert.equal(h.calls.filter(c => c.method === 'status').length, 1);
	await Promise.resolve();
	release({ ok: true });
	await promise;
	assert.ok(v.all.filter(n => n.tag === 'button' && !n.hidden && !/profiles-(start|apply)$/.test(n.attrs.id)).every(n => !n.disabled));
});

test('all RPC failures, negative and malformed results are visible and controls recover', async () => {
	const h = harness();
	const v = await h.render();
	for (const [method, label] of [['configure', 'Сохранить и применить'], ['control', 'Запустить'], ['check', 'Проверить'], ['logs', 'Показать журнал']]) {
		h.handlers[method] = () => { throw new Error(injected); };
		await v.button(label).attrs.click();
		assert.ok(text(v.get('zapret2-message')).includes(injected));
		assert.equal(h.notices.at(-1)[1].textContent, injected);
		assert.equal(h.notices.at(-1)[1].children.length, 0);
		assert.ok(v.all.filter(n => n.tag === 'button' && !n.hidden && !/profiles-(start|apply)$/.test(n.attrs.id)).every(n => !n.disabled));
	}
	h.handlers.control = () => ({ ok: false, error: injected });
	await v.button('Запустить').attrs.click();
	assert.ok(text(v.get('zapret2-message')).includes(injected));
	h.handlers.check = () => ({ ok: false, details: injected });
	await v.button('Проверить').attrs.click();
	assert.match(text(v.get('zapret2-message')), /Ошибка/);
	assert.ok(text(v.get('zapret2-check')).includes(injected));
	h.handlers.configure = () => ({});
	await v.button('Сохранить и применить').attrs.click();
	assert.match(text(v.get('zapret2-message')), /Ошибка/);
	h.handlers.status = () => { throw new Error('status unavailable'); };
	await h.pollers[0].callback();
	assert.match(text(v.get('zapret2-message')), /status unavailable/);
	assert.match(text(v.get('zapret2-state')), /неизвестно/);
});

test('initial status errors and malformed status do not appear as a stopped healthy service', async () => {
	for (const status of [() => { throw new Error('RPC denied'); }, () => ({})]) {
		const h = harness({ status });
		const v = await h.render();
		assert.match(text(v.get('zapret2-message')), /Ошибка/);
		assert.match(text(v.get('zapret2-state')), /неизвестно/);
		assert.match(text(v.get('zapret2-status-process')), /Неизвестно/);
		assert.equal(v.get('zapret2-clients').value, '');
		assert.equal(v.get('zapret2-client-mode').value, 'selected');
		assert.equal(v.get('zapret2-save').disabled, true);
		assert.equal(v.get('zapret2-start').disabled, true);
	}
});

test('stale in-flight polling cannot overwrite a newer control response', async () => {
	const h = harness();
	const v = await h.render();
	let release;
	h.handlers.status = () => new Promise(resolve => { release = resolve; });
	const pending = h.pollers[0].callback();
	await Promise.resolve();
	h.handlers.status = () => ({ ...h.state, running: true });
	await v.button('Запустить').attrs.click();
	assert.match(text(v.get('zapret2-state')), /Запущен/);
	release({ ...h.state, running: false });
	await pending;
	assert.match(text(v.get('zapret2-state')), /Запущен/);
});

test('post-write status failure is visible rather than reporting verified success', async () => {
	const h = harness();
	const v = await h.render();
	h.handlers.status = () => { throw new Error('refresh failed'); };
	await v.button('Сохранить и применить').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 1);
	assert.match(text(v.get('zapret2-message')), /Ошибка: refresh failed/);
	assert.match(text(v.get('zapret2-state')), /неизвестно/);
	assert.equal(v.get('zapret2-stop').disabled, true);
	assert.equal(v.get('zapret2-save').disabled, true);
});

test('poll errors recover, overlapping polls are suppressed, and read-only diagnostic values remain safe', async () => {
	const h = harness();
	h.state.engine_version = injected;
	h.state.package_version = injected;
	h.state.rule_counters = injected;
	h.state.clients = injected;
	h.state.destinations = injected;
	h.state.integrity_ok = false;
	h.state.table_present = true;
	const v = await h.render();
	for (const key of ['engine', 'package', 'counters', 'clients', 'destinations'])
		assert.ok(text(v.get('zapret2-status-' + key)).includes(injected));
	assert.match(text(v.get('zapret2-status-integrity')), /Нарушена/);
	assert.match(text(v.get('zapret2-status-table')), /Присутствует/);
	let release;
	h.handlers.status = () => new Promise(resolve => { release = resolve; });
	const pending = h.pollers[0].callback();
	await Promise.resolve();
	await h.pollers[0].callback();
	assert.equal(h.calls.filter(c => c.method === 'status').length, 2);
	release({ ...h.state, running: true });
	await pending;
	assert.match(text(v.get('zapret2-state')), /Запущен/);
	h.handlers.status = () => { throw new Error('down'); };
	await h.pollers[0].callback();
	assert.match(text(v.get('zapret2-state')), /неизвестно/);
	h.handlers.status = () => ({ ...h.state, running: false });
	await h.pollers[0].callback();
	assert.match(text(v.get('zapret2-state')), /Остановлен/);
});

test('malformed check and logs results are visible failures', async () => {
	const h = harness({ check: () => ({}), logs: () => ({}) });
	const v = await h.render();
	await v.button('Проверить').attrs.click();
	assert.match(text(v.get('zapret2-message')), /Ошибка:.*check/);
	await v.button('Показать журнал').attrs.click();
	assert.match(text(v.get('zapret2-message')), /Ошибка:.*logs/);
});

test('native tabs keep settings compact and diagnostics and journal separate', async () => {
	const h = harness();
	const v = await h.render();
	assert.equal(h.tabGroups.length, 1);
	const panes = h.tabGroups[0];
	assert.deepEqual(Array.from(panes, pane => pane.attrs['data-tab-title']), ['Настройки', 'Диагностика', 'Журнал', 'Профили']);
	assert.equal(panes[0].attrs['data-tab-active'], 'true');
	for (const id of ['zapret2-status-engine', 'zapret2-status-package', 'zapret2-status-profile', 'zapret2-status-queue', 'zapret2-status-counters', 'zapret2-status-warnings', 'zapret2-check']) {
		assert.ok(nodes(panes[1]).includes(v.get(id)), id);
		assert.ok(!nodes(panes[0]).includes(v.get(id)), id);
	}
	assert.ok(nodes(panes[2]).includes(v.get('zapret2-log')));
	assert.ok(!nodes(panes[0]).includes(v.get('zapret2-status-clients')));
	assert.ok(!nodes(panes[0]).includes(v.get('zapret2-status-destinations')));
	assert.ok(nodes(panes[0]).includes(v.get('zapret2-autostart')));
	assert.match(v.get('zapret2-clients').attrs.style, /width:100%/);
	assert.equal(v.get('zapret2-destinations').attrs.rows, '4');
	assert.ok(v.all.filter(n => n.tag === 'style').every(n => text(n).replace(/@media[^{}]+\{/g, '').split('}').filter(rule => rule.includes('{')).every(rule => rule.trim().startsWith('#zapret2-home '))));
	assert.doesNotMatch(text(v.tree), /Podkop|VPN/);
});

test('legacy status defaults to selected clients and disabled list auto-update without expanding scope', async () => {
	const h = harness();
	const v = await h.render();
	assert.equal(v.get('zapret2-client-mode').value, 'selected');
	assert.equal(v.get('zapret2-auto-update').checked, false);
	assert.equal(v.get('zapret2-clients').parentNode.parentNode.hidden, false);
	assert.equal(v.get('zapret2-clients').value, h.state.clients);
	assert.equal(v.get('zapret2-destinations').value, h.state.destinations);
	assert.ok(mainCalls(h).every(c => c.method === 'status'));
	for (const id of ['flowseal', 'cloudflare', 'hetzner', 'cloudfront', 'ovh', 'digitalocean']) {
		assert.equal(v.get('zapret2-list-' + id).checked, false);
		assert.match(text(v.get('zapret2-list-state-' + id)), /не загружен/);
	}
	assert.equal(v.get('zapret2-lists-updated').style.display, 'none');
});

test('all LAN mode is explicit, hides clients, preserves unsaved selection and sends new RPC parameters', async () => {
	const h = harness();
	const v = await h.render();
	v.get('zapret2-client-mode').value = 'all';
	v.get('zapret2-client-mode').attrs.change();
	assert.equal(v.get('zapret2-clients').parentNode.parentNode.hidden, true);
	v.get('zapret2-clients').value = 'invalid hidden client';
	v.get('zapret2-destinations').value = '';
	v.get('zapret2-list-flowseal').checked = true;
	v.get('zapret2-list-cloudflare').checked = true;
	v.get('zapret2-auto-update').checked = true;
	await v.button('Сохранить и применить').attrs.click();
	assert.deepEqual(h.calls.find(c => c.method === 'configure').args, ['', '', false, 'all', 'flowseal cloudflare', true]);
	assert.ok(!h.calls.some(c => c.method === 'control'));
	v.get('zapret2-client-mode').value = 'selected';
	v.get('zapret2-client-mode').attrs.change();
	assert.equal(v.get('zapret2-clients').parentNode.parentNode.hidden, false);
	assert.equal(v.get('zapret2-clients').value, 'invalid hidden client');
	const configure = h.declarations.find(d => d.method === 'configure');
	assert.deepEqual(Array.from(configure.params), ['clients', 'destinations', 'autostart', 'client_mode', 'lists', 'auto_update']);
	assert.match(text(v.tree), /устройства LAN, кроме роутера/);
});

test('selected clients cannot be empty even with community lists selected', async () => {
	const h = harness();
	const v = await h.render();
	v.get('zapret2-list-flowseal').checked = true;
	v.get('zapret2-clients').value = ' \n ';
	await v.button('Сохранить и применить').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 0);
	assert.match(text(v.get('zapret2-message')), /Клиенты/);
	assert.equal(v.get('zapret2-client-mode').value, 'selected');
});

test('empty destination scope is rejected in both modes, lists alone and manual IPs alone are accepted', async () => {
	const h = harness();
	const v = await h.render();
	v.get('zapret2-destinations').value = '';
	for (const mode of ['selected', 'all']) {
		v.get('zapret2-client-mode').value = mode;
		await v.button('Сохранить и применить').attrs.click();
		assert.match(text(v.get('zapret2-message')), /хотя бы один список/);
	}
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 0);
	v.get('zapret2-list-hetzner').checked = true;
	await v.button('Сохранить и применить').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 1);
	v.get('zapret2-list-hetzner').checked = false;
	v.get('zapret2-destinations').value = '65.108.59.85/32';
	await v.button('Сохранить и применить').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 2);
	v.get('zapret2-list-ovh').checked = true;
	v.get('zapret2-destinations').value = 'example.com';
	await v.button('Сохранить и применить').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 2);
	assert.match(text(v.get('zapret2-message')), /недопустимый IPv4/);
});

test('new status initializes saved lists and mode, polling refreshes catalog without clobbering any inputs', async () => {
	const h = harness();
	Object.assign(h.state, {
		client_mode: 'all', lists: 'flowseal\n cloudfront', auto_update: true,
		list_catalog: [{ id: 'flowseal', title: 'Flowseal new', description: 'Catalog description', url: 'https://example.invalid/list' }],
		list_state: { flowseal: { count: 123, updated: '2026-10-14', sha256: 'a'.repeat(64), error: '' } }
	});
	const v = await h.render();
	assert.equal(v.get('zapret2-client-mode').value, 'all');
	assert.equal(v.get('zapret2-clients').parentNode.parentNode.hidden, true);
	assert.equal(v.get('zapret2-list-flowseal').checked, true);
	assert.equal(v.get('zapret2-list-cloudfront').checked, true);
	assert.equal(v.get('zapret2-auto-update').checked, true);
	assert.equal(text(v.get('zapret2-list-label-flowseal')), 'Flowseal');
	assert.match(v.get('zapret2-list-label-flowseal').title, /Catalog description/);
	assert.match(text(v.get('zapret2-list-state-flowseal')), /123 сетей/);
	assert.match(text(v.get('zapret2-lists-updated')), /2026-10-14/);
	v.get('zapret2-list-flowseal').checked = false;
	v.get('zapret2-list-ovh').checked = true;
	v.get('zapret2-auto-update').checked = false;
	v.get('zapret2-destinations').value = '65.108.59.85';
	v.get('zapret2-client-mode').value = 'selected';
	v.get('zapret2-client-mode').attrs.change();
	h.state.list_catalog[0].title = 'Refreshed catalog';
	h.state.list_catalog[0].description = 'Refreshed description';
	h.state.list_state.flowseal.count = 456;
	await h.pollers[0].callback();
	assert.equal(text(v.get('zapret2-list-label-flowseal')), 'Flowseal');
	assert.match(v.get('zapret2-list-label-flowseal').title, /Refreshed description/);
	assert.match(text(v.get('zapret2-list-state-flowseal')), /456/);
	assert.equal(v.get('zapret2-list-flowseal').checked, false);
	assert.equal(v.get('zapret2-list-ovh').checked, true);
	assert.equal(v.get('zapret2-auto-update').checked, false);
	assert.equal(v.get('zapret2-destinations').value, '65.108.59.85');
	assert.equal(v.get('zapret2-client-mode').value, 'selected');
	assert.equal(v.get('zapret2-clients').parentNode.parentNode.hidden, false);
});

test('catalog titles, descriptions, list errors, checksums and update errors remain safe text', async () => {
	const h = harness();
	Object.assign(h.state, {
		list_catalog: [{ id: 'flowseal', title: injected, description: injected, url: 'javascript:alert(1)' }, { id: 'evil', title: injected }],
		list_state: { flowseal: { count: 1, updated: injected, sha256: injected, error: injected } }, update_error: injected
	});
	const v = await h.render();
	assert.ok(!text(v.get('zapret2-list-choices')).includes(injected));
	assert.ok(v.get('zapret2-list-label-flowseal').title.includes(injected));
	assert.ok(text(v.get('zapret2-status-list_details')).includes(injected));
	assert.ok(text(v.get('zapret2-status-update_error')).includes(injected));
	assert.equal(v.get('zapret2-list-evil'), undefined);
	assert.ok(!v.all.some(n => ['img', 'script', 'a'].includes(n.tag)));
	assert.equal(v.all.filter(n => n.attrs.type === 'checkbox').length, 33);
});

test('list update is fixed zero-argument RPC, reads back state and blocks repeated pending updates', async () => {
	const h = harness();
	const v = await h.render();
	h.handlers.update_lists = () => { h.state.update_running = true; return { ok: true, pending: true }; };
	await v.button('Обновить списки').attrs.click();
	assert.deepEqual(h.calls.find(c => c.method === 'update_lists').args, []);
	assert.deepEqual(Array.from(h.declarations.find(d => d.method === 'update_lists').params), []);
	assert.equal(v.get('zapret2-update-lists').disabled, true);
	assert.match(text(v.get('zapret2-status-update')), /выполняется/);
	await v.button('Обновить списки').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'update_lists').length, 1);
	h.state.update_running = false;
	h.state.list_state = { flowseal: { count: 50, updated: 'now', sha256: 'test-digest' } };
	await h.pollers[0].callback();
	assert.equal(v.get('zapret2-update-lists').disabled, false);
	assert.match(text(v.get('zapret2-list-state-flowseal')), /50 сетей/);
	assert.match(text(v.get('zapret2-lists-updated')), /now/);
	assert.ok(!h.calls.some(c => ['configure', 'control'].includes(c.method)));
	assert.match(text(v.tree), /только пока основная служба запущена/);
});

test('update RPC rejection, malformed result and post-update readback failure are reported', async () => {
	const h = harness();
	const v = await h.render();
	for (const result of [{}, { ok: false, error: injected }, { ok: true, pending: false }]) {
		h.handlers.update_lists = () => result;
		await v.button('Обновить списки').attrs.click();
		assert.match(text(v.get('zapret2-message')), /Ошибка/);
		assert.equal(v.get('zapret2-update-lists').disabled, false);
	}
	h.handlers.update_lists = () => { throw new Error('update denied'); };
	await v.button('Обновить списки').attrs.click();
	assert.match(text(v.get('zapret2-message')), /update denied/);
	h.handlers.update_lists = () => ({ ok: true, pending: true });
	h.handlers.status = () => { throw new Error('readback failed'); };
	await v.button('Обновить списки').attrs.click();
	assert.match(text(v.get('zapret2-message')), /readback failed/);
	assert.match(text(v.get('zapret2-state')), /неизвестно/);
});

test('active-service saving delegates restart to configure and reads back without an extra control RPC', async () => {
	const h = harness();
	h.state.running = true;
	const v = await h.render();
	assert.equal(v.get('zapret2-save').disabled, false);
	v.get('zapret2-destinations').value = '65.108.59.85/32';
	await v.button('Сохранить и применить').attrs.click();
	assert.deepEqual(mainCalls(h).map(c => c.method), ['status', 'configure', 'status']);
	assert.equal(h.state.running, true);
	assert.equal(v.get('zapret2-destinations').value, '65.108.59.85/32');
	assert.equal(text(v.get('zapret2-message')), '');
	assert.equal(text(v.tree).split('Запущенная служба перезапустится для применения изменений; остановленная не запускается.').length - 1, 1);
	h.handlers.control = () => { h.state.running = false; return { ok: true }; };
	await v.button('Остановить всё').attrs.click();
	assert.equal(v.get('zapret2-save').disabled, false);
	await v.button('Сохранить и применить').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 2);
});

test('service actions reflect stopped, running and unknown states and hidden actions cannot execute', async () => {
	const h = harness();
	const v = await h.render();
	async function assertActions(visible) {
		for (const id of ['start', 'stop', 'restart']) {
			const button = v.get('zapret2-' + id);
			const shown = visible.includes(id);
			assert.equal(button.hidden, !shown, id);
			assert.equal(button.style.display, shown ? '' : 'none', id);
			assert.equal(button.disabled, !shown, id);
			if (!shown) await button.attrs.click();
		}
	}
	await assertActions(['start']);
	await v.button('Запустить').attrs.click();
	await assertActions(['stop', 'restart']);
	assert.equal(text(v.get('zapret2-message')), '');
	await v.button('Остановить всё').attrs.click();
	await assertActions(['start']);
	h.handlers.status = () => { throw new Error('status denied'); };
	await h.pollers[0].callback();
	await assertActions([]);
	assert.equal(v.get('zapret2-save').disabled, true);
	assert.match(text(v.get('zapret2-message')), /status denied/);
	assert.deepEqual(h.calls.filter(c => c.method === 'control').map(c => c.args[0]), ['start', 'stop']);
});

test('pending list refresh blocks saving but polling preserves input edits', async () => {
	const h = harness();
	h.state.running = true;
	h.state.update_running = true;
	const v = await h.render();
	assert.equal(v.get('zapret2-save').disabled, true);
	await v.get('zapret2-save').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 0);
	v.get('zapret2-destinations').value = '65.108.59.85';
	h.state.update_running = false;
	await h.pollers[0].callback();
	assert.equal(v.get('zapret2-save').disabled, false);
	assert.equal(v.get('zapret2-destinations').value, '65.108.59.85');
});

test('configure errors retain rollback outcome, read back even on failure, and preserve edits', async () => {
	for (const rolled_back of [true, false]) {
		const h = harness();
		h.state.running = true;
		const v = await h.render();
		v.get('zapret2-clients').value = '192.168.1.77';
		h.handlers.configure = () => { h.state.running = rolled_back; return { ok: false, error: injected, rolled_back }; };
		await v.get('zapret2-save').attrs.click();
		assert.deepEqual(mainCalls(h).map(c => c.method), ['status', 'configure', 'status']);
		assert.ok(text(v.get('zapret2-message')).includes(injected));
		assert.match(text(v.get('zapret2-message')), rolled_back ? /Предыдущие настройки восстановлены/ : /Откат не выполнен/);
		assert.match(text(v.get('zapret2-state')), rolled_back ? /Запущен/ : /Остановлен/);
		assert.equal(v.get('zapret2-clients').value, '192.168.1.77');
		assert.ok(!v.all.some(n => ['script', 'img'].includes(n.tag)));
	}
});

test('failed write and failed readback both remain visible and invalidate unsafe actions', async () => {
	const h = harness();
	const v = await h.render();
	h.handlers.configure = () => ({ ok: false, error: 'apply failed', rolled_back: false });
	h.handlers.status = () => { throw new Error('readback failed'); };
	await v.get('zapret2-save').attrs.click();
	assert.match(text(v.get('zapret2-message')), /apply failed/);
	assert.match(text(v.get('zapret2-message')), /readback failed/);
	for (const id of ['save', 'start', 'stop', 'restart']) assert.equal(v.get('zapret2-' + id).disabled, true);
});

test('active save stays busy until status readback completes and ignores duplicate saves', async () => {
	const h = harness();
	h.state.running = true;
	const v = await h.render();
	let release;
	h.handlers.status = () => new Promise(resolve => { release = resolve; });
	const pending = v.get('zapret2-save').attrs.click();
	for (let i = 0; i < 20 && !release; i++) await Promise.resolve();
	assert.equal(typeof release, 'function', 'Save must begin status readback');
	assert.match(text(v.get('zapret2-message')), /Выполняется:/);
	for (const id of ['save', 'stop', 'restart', 'clients']) assert.equal(v.get('zapret2-' + id).disabled, true);
	await v.get('zapret2-save').attrs.click();
	await h.pollers[0].callback();
	assert.deepEqual(mainCalls(h).map(c => c.method), ['status', 'configure', 'status']);
	release({ ...h.state });
	await pending;
	assert.equal(v.get('zapret2-save').disabled, false);
	assert.equal(text(v.get('zapret2-message')), '');
});

test('every rejected write still reads status before exposing its error', async () => {
	for (const [method, id] of [['configure', 'save'], ['control', 'start'], ['update_lists', 'update-lists']]) {
		const h = harness();
		const v = await h.render();
		h.handlers[method] = () => { h.state.running = true; throw new Error('transport failed'); };
		await v.get('zapret2-' + id).attrs.click();
		assert.deepEqual(mainCalls(h).map(c => c.method), ['status', method, 'status']);
		assert.match(text(v.get('zapret2-message')), /transport failed/);
		assert.match(text(v.get('zapret2-state')), /Запущен/);
		assert.equal(v.get('zapret2-start').hidden, true);
	}
});

test('stale polling failures cannot downgrade newer state or show a stale error', async () => {
	const h = harness();
	const v = await h.render();
	let reject;
	h.handlers.status = () => new Promise((resolve, fail) => { reject = fail; });
	const pending = h.pollers[0].callback();
	await Promise.resolve();
	h.handlers.status = () => ({ ...h.state, running: true });
	await v.button('Запустить').attrs.click();
	reject(new Error('stale failure'));
	await pending;
	assert.match(text(v.get('zapret2-state')), /Запущен/);
	assert.doesNotMatch(text(v.get('zapret2-message')), /stale failure/);
});

test('community lists show compact fixed titles, muted counts and one shared timestamp', async () => {
	const h = harness();
	const ids = ['flowseal', 'cloudflare', 'hetzner', 'cloudfront', 'ovh', 'digitalocean'];
	h.state.list_catalog = ids.map(id => ({ id, title: 'Cluttered title / Discord / YouTube', description: 'Общественный список IPv4-подсетей; не список доменов' }));
	h.state.list_state = Object.fromEntries(ids.map(id => [id, { count: 26037, updated: 1791971241, sha256: 'a'.repeat(64) }]));
	const v = await h.render();
	const choices = v.get('zapret2-list-choices');
	assert.doesNotMatch(text(choices), /Общественный|Discord|YouTube|Обновл/);
	assert.ok(!nodes(choices).some(n => n.attrs.class === 'cbi-value-description'));
	assert.deepEqual(ids.map(id => text(v.get('zapret2-list-label-' + id))), ['Flowseal', 'Cloudflare', 'Hetzner', 'CloudFront', 'OVH', 'DigitalOcean']);
	for (const id of ids) {
		assert.equal(text(v.get('zapret2-list-state-' + id)), '26 037 сетей');
		assert.match(v.get('zapret2-list-label-' + id).title, /Общественный/);
	}
	const timestamp = new Date(1791971241 * 1000).toLocaleString();
	assert.equal(text(v.tree).split(timestamp).length - 1, 1);
	assert.match(text(v.get('zapret2-lists-updated')), /Обновлены:/);
	assert.match(text(v.tree), /Подсети серверов/);
	assert.doesNotMatch(text(v.tree), /Podkop|VPN/);
	h.state.list_state.cloudflare.updated = 1791971242;
	await h.pollers[0].callback();
	assert.match(text(v.get('zapret2-lists-updated')), /Последнее обновление:/);
	assert.ok(text(v.get('zapret2-lists-updated')).endsWith(new Date(1791971242 * 1000).toLocaleString()));
	assert.ok(v.get('zapret2-list-label-flowseal').title.includes(timestamp));
	h.state.list_state = { flowseal: { count: 26037, updated: '1791971241' } };
	await h.pollers[0].callback();
	assert.ok(text(v.get('zapret2-lists-updated')).endsWith(timestamp));
});

test('diagnostics avoid native form offsets, collapse advanced data and hide empty errors', async () => {
	const h = harness();
	h.state.warnings = ['Только выбранные прямые IPv4 TCP/443. VPN-маршруты не изменяются.', 'HTTP/3, IPv6 и работа приложений целиком этой версией не проверяются.'];
	const v = await h.render();
	const diagnosticNodes = nodes(h.tabGroups[0][1]);
	assert.ok(!diagnosticNodes.some(n => /cbi-value/.test(n.attrs.class || '')));
	assert.equal(diagnosticNodes.filter(n => n.tag === 'details').length, 3);
	assert.ok(diagnosticNodes.filter(n => n.tag === 'details').every(n => !n.attrs.open));
	assert.equal(v.get('zapret2-status-update_error').parentNode.style.display, 'none');
	assert.equal(v.get('zapret2-status-warnings').parentNode.style.display, 'none');
	assert.equal(v.get('zapret2-status-package').parentNode, v.get('zapret2-status-engine').parentNode);
	h.state.update_error = injected;
	h.state.warnings.push('Состояния процесса и nft-таблицы расходятся.');
	await h.pollers[0].callback();
	assert.equal(v.get('zapret2-status-update_error').parentNode.style.display, '');
	assert.match(text(v.get('zapret2-status-warnings')), /расходятся/);
});

test('completed update failures remain visible and successful recovery hides the error row', async () => {
	const h = harness();
	h.state.update_running = true;
	const v = await h.render();
	h.state.update_running = false;
	h.state.update_error = 'Download failed';
	await h.pollers[0].callback();
	assert.match(text(v.get('zapret2-message')), /Download failed/);
	assert.equal(v.get('zapret2-status-update_error').parentNode.style.display, '');
	assert.equal(v.get('zapret2-update-lists').disabled, false);
	h.state.update_error = '';
	await h.pollers[0].callback();
	assert.equal(v.get('zapret2-status-update_error').parentNode.style.display, 'none');
});

function chooseProfiles(v, profiles = ['alt1', 'stock'], targets = ['gitlab', 'unitask', 'tavily']) {
	for (const [kind, ids] of [['profile', profiles], ['target', targets]]) {
		for (const id of kind === 'profile' ? profileIds : targetIds) { const input = v.get('zapret2-test-' + kind + '-' + id); if (!input) continue; input.checked = ids.includes(id); input.attrs.change(); }
	}
}
function profileRow(extra = {}) {
	return { protocol: 'tcp', profile: 'alt1', target: 'gitlab', repeat: 1, status: 200, bytes: 42, time_total: 0.4, full_match: true, failure: '', ...extra };
}

test('Profiles offers six profiles, five targets, explicit test/apply selections and repeat 1', async () => {
	const h = harness(), v = await h.render(), pane = v.get('zapret2-protocol-panel');
	assert.equal(v.get('zapret2-test-repeat').value, '1');
	assert.equal(nodes(pane).filter(n => n.attrs.type === 'checkbox' && n.checked).length, 5);
	assert.equal(v.get('zapret2-profiles-start').disabled, false);
	assert.equal(nodes(pane).filter(n => n.tag === 'button').length, 6);
	assert.equal(v.get('zapret2-apply-profile').value, 'alt1');
	assert.equal(v.get('zapret2-profiles-apply').disabled, true);
	assert.equal(text(v.get('zapret2-active-profile')), 'Основной · alt1');
	assert.equal(nodes(pane).filter(n => n.attrs.type === 'checkbox').length, 11);
	assert.match(text(pane), /60 проверок.*1350 секунд/);
	assert.match(text(pane), /минут/);
	assert.equal(text(pane).split('видео, gateway и голосовая связь не проверены').length - 1, 1);
	assert.ok(!nodes(pane).some(n => n.tag === 'textarea' || n.attrs.type === 'text'));
	assert.doesNotMatch(text(pane), /previously_verified|experimental/);
	assert.match(text(pane), /Основной|Базовый|Разделение с перекрытием/);
	assert.match(text(pane), /канал связи/); assert.match(text(pane), /не гарантия/);
	await h.pollers[1].callback();
	assert.ok(!h.calls.some(c => c.method === 'protocols_test'));
	assert.equal(h.calls.filter(c => c.method === 'protocols_status').length, 1, 'Idle job is not repeatedly polled');
	for (const method of ['protocols_catalog', 'protocols_status', 'protocols_test', 'protocols_apply']) {
		assert.deepEqual(Array.from(h.declarations.find(d => d.method === method).params), method === 'protocols_test' ? ['protocol', 'profiles', 'targets', 'repeat'] : method === 'protocols_apply' ? ['protocol', 'enabled', 'profile'] : []);
	}
});

test('pending profile launch polls separately, shows partial metrics and blocks cleanup without blocking normal save', async () => {
	const h = harness(), v = await h.render(); chooseProfiles(v); v.get('zapret2-test-repeat').value = '2';
	await v.get('zapret2-profiles-start').attrs.click();
	assert.deepEqual(h.calls.find(c => c.method === 'protocols_test').args, ['tcp', 'alt1 stock', 'gitlab unitask tavily', 2]);
	assert.match(text(v.get('zapret2-profiles-state')), /результат ещё не подтверждён/);
	assert.match(text(v.get('zapret2-profiles-state')), /0\/12/);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	assert.equal(v.get('zapret2-save').disabled, false);
	assert.equal(v.get('zapret2-test-profile-alt1').disabled, true);
	await v.get('zapret2-profiles-start').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'protocols_test').length, 1);
	Object.assign(h.profilesState, { state: 'results', running: true, results: [profileRow(), profileRow({ profile: 'stock', target: 'tavily', status: 0, bytes: 0, time_total: 5, full_match: false, failure: 'connect_or_setup' })] });
	await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-state')), /2\/12/);
	assert.match(text(v.get('zapret2-profiles-technical')), /alt1 \/ gitlab #1 · HTTP 200 · 42 B · 0.4 s · Полная загрузка \(full_match\)/);
	assert.match(text(v.get('zapret2-profiles-technical')), /stock \/ tavily.*connect_or_setup/);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	await v.get('zapret2-save').attrs.click();
	assert.equal(h.calls.filter(c => c.method === 'configure').length, 1);
	assert.equal(text(v.get('zapret2-status-profile')), h.state.profile);
	h.profilesState.running = false; await h.pollers[1].callback();
	assert.equal(v.get('zapret2-profiles-start').disabled, false);
	assert.equal(v.get('zapret2-test-repeat').value, '2');
	assert.ok(v.get('zapret2-test-profile-stock').checked);
});

test('cleanup failure on initial load retains error, partial rows and running lock', async () => {
	const h = harness(); Object.assign(h.profilesState, { state: 'error', running: true, error: injected, results: [profileRow({ full_match: false, failure: injected })] });
	const v = await h.render(); chooseProfiles(v);
	assert.ok(text(v.get('zapret2-profiles-state')).includes(injected));
	assert.ok(text(v.get('zapret2-profiles-technical')).includes(injected));
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	assert.equal(v.get('zapret2-save').disabled, false);
	await h.pollers[1].callback(); await v.get('zapret2-profiles-start').attrs.click();
	assert.ok(!h.calls.some(c => c.method === 'protocols_test'));
	assert.ok(!v.all.some(n => ['img', 'script'].includes(n.tag)));
});

test('profile catalog/status absence and malformed data never disable unrelated settings', async () => {
	for (const overrides of [
		{ protocols_catalog: () => { throw new Error('No profiles RPC'); } },
		{ protocols_catalog: () => ({ ok: true, catalog: { groups: [] } }) },
		{ protocols_status: () => ({ ok: true, catalog: protocolCatalog(profilesCatalog), data: { state: 'idle', running: 'false', results: [] } }) },
		{ protocols_status: () => ({}) },
		{ protocols_status: () => { throw new Error(injected); } }
	]) {
		const h = harness(overrides), v = await h.render(); chooseProfiles(v);
		assert.match(text(v.get('zapret2-profiles-state')), /Ошибка/);
		assert.equal(v.get('zapret2-profiles-start').disabled, true);
		assert.equal(v.get('zapret2-save').disabled, false);
		await v.get('zapret2-save').attrs.click();
		assert.equal(h.calls.filter(c => c.method === 'configure').length, 1);
		assert.equal(text(v.get('zapret2-message')), '');
	}
});

test('profile launch RPC rejection/malformed response reads back and does not claim success', async () => {
	for (const reply of [{}, { ok: false, error: injected }, { ok: true, pending: false }, { ok: true, pending: true, job_id: 'bad' }]) {
		const h = harness({ protocols_test: () => reply }), v = await h.render(); chooseProfiles(v, ['alt1'], ['gitlab']);
		await v.get('zapret2-profiles-start').attrs.click();
		assert.match(text(v.get('zapret2-profiles-state')), /Ошибка/);
		assert.equal(h.calls.filter(c => c.method === 'protocols_status').length, 3);
		assert.equal(v.get('zapret2-profiles-start').disabled, false);
		assert.ok(!mainCalls(h).some(c => c.method !== 'status'));
	}
	const h = harness(), v = await h.render(); chooseProfiles(v);
	h.handlers.protocols_test = () => { Object.assign(h.profilesState, { state: 'running', running: true }); throw new Error('Transport lost'); };
	await v.get('zapret2-profiles-start').attrs.click();
	assert.match(text(v.get('zapret2-profiles-state')), /Transport lost/);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
});

test('profile pending acknowledgment requires matching job status and recovers after readback failure', async () => {
	const h = harness(), v = await h.render(); chooseProfiles(v);
	h.handlers.protocols_test = () => ({ ok: true, pending: true, job_id: '777.888' });
	await v.get('zapret2-profiles-start').attrs.click();
	assert.match(text(v.get('zapret2-profiles-state')), /другой job_id/);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	Object.assign(h.profilesState, { job_id: '777.888', state: 'running', running: true, results: [profileRow()] });
	await h.pollers[1].callback();
	h.handlers.protocols_status = () => { throw new Error('Readback unavailable'); };
	await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-state')), /Readback unavailable/);
	assert.match(text(v.get('zapret2-profiles-technical')), /full_match/);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	h.handlers.protocols_status = () => ({ ok: true, catalog: protocolCatalog(profilesCatalog), data: { ...h.profilesState, state: 'results', running: false } });
	await h.pollers[1].callback();
	assert.equal(v.get('zapret2-profiles-start').disabled, false);
});

test('profile selection and repeat validation sends no arbitrary IDs or invalid repeat', async () => {
	const h = harness(), v = await h.render(); chooseProfiles(v, ['alt1'], ['gitlab']);
	v.get('zapret2-test-profile-alt1').value = 'https://evil.invalid/';
	v.get('zapret2-test-repeat').value = '3';
	await v.get('zapret2-profiles-start').attrs.click();
	assert.ok(!h.calls.some(c => c.method === 'protocols_test'));
	v.get('zapret2-test-repeat').value = '1';
	await v.get('zapret2-profiles-start').attrs.click();
	assert.deepEqual(h.calls.find(c => c.method === 'protocols_test').args, ['tcp', 'alt1', 'gitlab', 1]);
});

test('profile polling continues during an active save without releasing main busy controls', async () => {
	const h = harness(); h.state.running = true; Object.assign(h.profilesState, { state: 'running', running: true });
	const v = await h.render();
	let release; h.handlers.configure = () => new Promise(resolve => { release = resolve; });
	const saving = v.get('zapret2-save').attrs.click();
	for (let i = 0; i < 20 && !release; i++) await Promise.resolve();
	assert.equal(typeof release, 'function');
	h.profilesState.results = [profileRow()]; await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-technical')), /full_match/);
	assert.equal(v.get('zapret2-save').disabled, true);
	assert.equal(v.get('zapret2-stop').disabled, true);
	release({ ok: true }); await saving;
	assert.equal(v.get('zapret2-save').disabled, false);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
});

test('profile preflight catches another running job and overlapping polls are suppressed', async () => {
	const h = harness(), v = await h.render(); chooseProfiles(v);
	Object.assign(h.profilesState, { state: 'running', running: true });
	await v.get('zapret2-profiles-start').attrs.click();
	assert.ok(!h.calls.some(c => c.method === 'protocols_test'));
	let release;
	h.handlers.protocols_status = () => new Promise(resolve => { release = resolve; });
	const before = h.calls.length, polling = h.pollers[1].callback(); await Promise.resolve();
	await h.pollers[1].callback();
	assert.equal(h.calls.length, before + 1);
	release({ ok: true, catalog: protocolCatalog(profilesCatalog), data: { state: 'idle', running: false, results: [] } }); await polling;
	assert.equal(v.get('zapret2-profiles-start').disabled, false);
});

test('profile result trust boundary rejects unknown IDs, oversized rows and malformed metrics', async () => {
	for (const results of [[profileRow({ profile: 'arbitrary' })], [profileRow({ target: 'https://evil.invalid' })], [profileRow({ time_total: '0.4' })], Array(61).fill(profileRow())]) {
		const h = harness(); Object.assign(h.profilesState, { state: 'results', results });
		const v = await h.render(); chooseProfiles(v);
		assert.equal(v.get('zapret2-profiles-start').disabled, true);
		assert.match(text(v.get('zapret2-profiles-state')), /Некорректный ответ/);
		assert.equal(v.get('zapret2-save').disabled, false);
	}
});

function candidate(v, id = 'stock') {
	v.get('zapret2-apply-profile').value = id;
	v.get('zapret2-apply-profile').attrs.change();
}

test('select all and clear selection expose the full 60-row budget without automatic apply', async () => {
	const h = harness(), v = await h.render();
	for (const kind of ['profile', 'target']) {
		v.get('zapret2-test-' + kind + '-all').attrs.click();
		assert.equal(v.get('zapret2-profiles-start').disabled, false);
		v.get('zapret2-test-' + kind + '-clear').attrs.click();
		assert.equal(v.get('zapret2-profiles-start').disabled, true);
		v.get('zapret2-test-' + kind + '-all').attrs.click();
	}
	v.get('zapret2-test-repeat').value = '2';
	await v.get('zapret2-profiles-start').attrs.click();
	assert.deepEqual(h.calls.find(c => c.method === 'protocols_test').args, ['tcp', profileIds.join(' '), targetIds.join(' '), 2]);
	assert.match(text(v.get('zapret2-profiles-state')), /0\/60/);
	const results = profileIds.flatMap(profile => targetIds.flatMap(target => [1, 2].map(repeat => profileRow({ profile, target, repeat }))));
	Object.assign(h.profilesState, { state: 'results', running: false, results });
	await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-state')), /60\/60/);
	assert.equal(text(v.get('zapret2-profiles-technical')).split('(full_match)').length - 1, 60);
	assert.equal(nodes(v.get('zapret2-profiles-results')).filter(n => n.attrs['data-result'] === 'success').length, 30);
	assert.equal(text(v.get('zapret2-active-profile')), 'Основной · alt1');
	assert.equal(v.get('zapret2-apply-profile').value, 'alt1');
	assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
});

test('manual apply is fixed three-parameter RPC, verifies actual saved ID and preserves every unsaved input', async () => {
	for (const running of [false, true]) {
		const h = harness(); h.state.running = running;
		const v = await h.render();
		v.get('zapret2-clients').value = 'unsaved clients';
		v.get('zapret2-destinations').value = 'unsaved destinations';
		v.get('zapret2-list-ovh').checked = true;
		v.get('zapret2-client-mode').value = 'all';
		v.get('zapret2-autostart').checked = true;
		v.get('zapret2-auto-update').checked = true;
		candidate(v, 'alt1');
		await v.get('zapret2-profiles-apply').attrs.click();
		assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
		candidate(v);
		await v.get('zapret2-profiles-apply').attrs.click();
		assert.deepEqual(h.calls.find(c => c.method === 'protocols_apply').args, ['tcp', true, 'stock']);
		assert.equal(text(v.get('zapret2-active-profile')), 'Базовый · stock');
		assert.equal(v.get('zapret2-profiles-apply').disabled, true);
		assert.equal(text(v.get('zapret2-message')), '');
		assert.equal(h.state.running, running);
		assert.equal(v.get('zapret2-clients').value, 'unsaved clients');
		assert.equal(v.get('zapret2-destinations').value, 'unsaved destinations');
		assert.equal(v.get('zapret2-client-mode').value, 'all');
		for (const id of ['list-ovh', 'autostart', 'auto-update']) assert.equal(v.get('zapret2-' + id).checked, true);
		assert.ok(!h.calls.some(c => ['configure', 'control'].includes(c.method)));
	}
});

test('apply candidate selection, test result and unknown/missing profile_id never claim a false active profile', async () => {
	const h = harness(), v = await h.render(); candidate(v);
	assert.equal(text(v.get('zapret2-active-profile')), 'Основной · alt1');
	for (const id of [undefined, injected, 'invalid']) {
		h.state.profile_id = id; await h.pollers[0].callback();
		assert.match(text(v.get('zapret2-active-profile')), /Неизвестен/);
		assert.equal(v.get('zapret2-profiles-apply').disabled, true);
		await v.get('zapret2-profiles-apply').attrs.click();
	}
	h.state.profile_id = 'alt1'; await h.pollers[0].callback();
	candidate(v, injected); await v.get('zapret2-profiles-apply').attrs.click();
	assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
	assert.ok(!v.all.some(n => ['img', 'script'].includes(n.tag)));
});

test('apply is blocked by main pending/recovery/updater, diagnostic running/cleanup/unknown and busy actions', async () => {
	for (const patch of [{ configure_pending: true }, { configure_recovery_required: true }, { update_running: true }]) {
		const h = harness(); Object.assign(h.state, patch); const v = await h.render(); candidate(v);
		assert.equal(v.get('zapret2-profiles-apply').disabled, true);
		await v.get('zapret2-profiles-apply').attrs.click();
		assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
	}
	for (const patch of [{ state: 'pending', running: false }, { state: 'running', running: false }, { state: 'error', running: true }, { state: 'results', running: true }]) {
		const h = harness(); Object.assign(h.profilesState, patch); const v = await h.render(); candidate(v);
		assert.equal(v.get('zapret2-profiles-apply').disabled, true);
	}
	for (const method of ['status', 'protocols_status']) {
		const h = harness({ [method]: () => { throw new Error('unavailable'); } }), v = await h.render(); candidate(v);
		assert.equal(v.get('zapret2-profiles-apply').disabled, true);
	}
});

test('apply and test launch serialize both directions and ignore duplicate requests', async () => {
	const h = harness(), v = await h.render(); chooseProfiles(v); candidate(v);
	let release;
	h.handlers.protocols_test = () => new Promise(resolve => { release = resolve; });
	const launch = v.get('zapret2-profiles-start').attrs.click();
	for (let i = 0; i < 30 && !release; i++) await Promise.resolve();
	assert.equal(typeof release, 'function');
	assert.equal(v.get('zapret2-profiles-apply').disabled, true);
	await v.get('zapret2-profiles-apply').attrs.click();
	release({ ok: false, error: 'test rejected' }); await launch;
	h.handlers.protocols_apply = () => new Promise(resolve => { release = resolve; }); release = null;
	const applying = v.get('zapret2-profiles-apply').attrs.click();
	for (let i = 0; i < 30 && !release; i++) await Promise.resolve();
	assert.equal(typeof release, 'function');
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	assert.equal(v.get('zapret2-save').disabled, true);
	await v.get('zapret2-profiles-start').attrs.click(); await v.get('zapret2-profiles-apply').attrs.click();
	h.state.profile_id = 'stock'; release({ ok: true }); await applying;
	assert.equal(h.calls.filter(c => c.method === 'protocols_apply').length, 1);
	assert.equal(h.calls.filter(c => c.method === 'protocols_test').length, 1);
});

test('apply preflight detects newly pending main or diagnostic state before sending a write', async () => {
	for (const target of ['main', 'profiles']) {
		const h = harness(), v = await h.render(); candidate(v);
		if (target === 'main') h.state.update_running = true;
		else Object.assign(h.profilesState, { running: true, state: 'running' });
		await v.get('zapret2-profiles-apply').attrs.click();
		assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
		assert.match(text(v.get('zapret2-message')), /Ошибка/);
		assert.equal(v.get('zapret2-profiles-apply').disabled, true);
	}
});

test('pending apply stays busy despite matching profile_id until matching terminal job readback', async () => {
	const h = harness(), v = await h.render(); candidate(v);
	let applied = false, reads = 0;
	h.handlers.protocols_apply = () => {
		applied = true;
		Object.assign(h.state, { profile_id: 'stock', configure_pending: true, configure_job_id: 901, configure_result: { ok: true, job_id: 901 } });
		return { ok: true, pending: true, job_id: 901 };
	};
	h.handlers.status = () => {
		if (applied && ++reads === 2) h.state.configure_pending = false;
		return { ...h.state };
	};
	const applying = v.get('zapret2-profiles-apply').attrs.click();
	await new Promise(resolve => setTimeout(resolve, 20));
	assert.equal(v.get('zapret2-profiles-apply').disabled, true);
	assert.match(text(v.get('zapret2-message')), /Выполняется/);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	await applying;
	assert.equal(text(v.get('zapret2-message')), '');
	assert.equal(text(v.get('zapret2-active-profile')), 'Базовый · stock');
});

test('pending apply rejects mismatched jobs/results, missing terminal result and wrong final saved profile', async () => {
	for (const patch of [
		{ configure_job_id: 902 }, { configure_result: { ok: true, job_id: 902 } },
		{ configure_result: null }, { profile_id: 'alt1' }
	]) {
		const h = harness(), v = await h.render(); candidate(v);
		h.handlers.protocols_apply = () => {
			Object.assign(h.state, { configure_pending: false, configure_job_id: 901, configure_result: { ok: true, job_id: 901 }, profile_id: 'stock' }, patch);
			return { ok: true, pending: true, job_id: 901 };
		};
		await v.get('zapret2-profiles-apply').attrs.click();
		assert.match(text(v.get('zapret2-message')), /Ошибка/);
		assert.ok(h.calls.filter(c => c.method === 'status').length >= 3);
	}
});

test('apply rollback, transport/malformed failures and false terminal success remain visible after readback', async () => {
	for (const reply of [{}, { ok: false, error: injected, rolled_back: true }, { ok: false, error: injected, rolled_back: false }, { ok: true }, { ok: true, pending: 'true' }, { ok: true, pending: true, job_id: 'bad' }]) {
		const h = harness({ protocols_apply: () => reply }), v = await h.render(); candidate(v);
		await v.get('zapret2-profiles-apply').attrs.click();
		assert.match(text(v.get('zapret2-message')), /Ошибка/);
		assert.equal(text(v.get('zapret2-active-profile')), 'Основной · alt1');
		if (typeof reply.rolled_back === 'boolean') assert.match(text(v.get('zapret2-message')), reply.rolled_back ? /восстановлены/ : /Откат не выполнен/);
		assert.ok(!v.all.some(n => ['img', 'script'].includes(n.tag)));
		assert.equal(h.calls.filter(c => c.method === 'status').length, 3);
	}
	const h = harness(), v = await h.render(); candidate(v);
	h.handlers.protocols_apply = () => { h.handlers.status = () => { throw new Error('readback failed'); }; throw new Error('transport lost'); };
	await v.get('zapret2-profiles-apply').attrs.click();
	assert.match(text(v.get('zapret2-message')), /transport lost/);
	assert.match(text(v.get('zapret2-message')), /readback failed/);
	assert.match(text(v.get('zapret2-active-profile')), /Неизвестен/);
	assert.equal(v.get('zapret2-profiles-apply').disabled, true);
});

test('pending apply rollback and recovery-required retain actual old profile and unsafe-action lock', async () => {
	for (const rolled_back of [true, false]) {
		const h = harness(), v = await h.render(); candidate(v);
		h.handlers.protocols_apply = () => {
			Object.assign(h.state, { configure_pending: false, configure_job_id: 901, configure_recovery_required: !rolled_back,
				configure_result: { ok: false, job_id: 901, error: injected, rolled_back } });
			return { ok: true, pending: true, job_id: 901 };
		};
		await v.get('zapret2-profiles-apply').attrs.click();
		assert.ok(text(v.get('zapret2-message')).includes(injected));
		assert.match(text(v.get('zapret2-message')), rolled_back ? /восстановлены/ : /Откат не выполнен/);
		assert.equal(text(v.get('zapret2-active-profile')), 'Основной · alt1');
		assert.equal(v.get('zapret2-profiles-apply').disabled, !rolled_back);
		assert.equal(v.get('zapret2-save').disabled, !rolled_back);
	}
});

test('pending/recovery/updater status fields reject non-boolean values instead of allowing apply', async () => {
	for (const key of ['configure_pending', 'configure_recovery_required', 'update_running']) {
		const h = harness(); h.state[key] = 'false'; const v = await h.render(); candidate(v);
		assert.equal(v.get('zapret2-profiles-apply').disabled, true);
		assert.match(text(v.get('zapret2-active-profile')), /Неизвестен/);
		assert.match(text(v.get('zapret2-message')), /Некорректный ответ status/);
	}
});

test('pending apply final readback must still show the matching terminal job and profile', async () => {
	for (const patch of [{ profile_id: 'fake' }, { configure_job_id: 999 }, { configure_pending: true }, { configure_pending: undefined }, { configure_recovery_required: true }]) {
		const h = harness(), v = await h.render(); candidate(v);
		let applied = false, reads = 0;
		h.handlers.protocols_apply = () => {
			applied = true;
			Object.assign(h.state, { profile_id: 'stock', configure_job_id: 901, configure_pending: false, configure_result: { ok: true, job_id: 901 } });
			return { ok: true, pending: true, job_id: 901 };
		};
		h.handlers.status = () => {
			if (applied && ++reads === 2) Object.assign(h.state, patch);
			return { ...h.state };
		};
		await v.get('zapret2-profiles-apply').attrs.click();
		assert.match(text(v.get('zapret2-message')), /Ошибка/);
	}
});

test('later six-parameter Settings save preserves the explicitly applied profile', async () => {
	const h = harness(), v = await h.render(); candidate(v, 'overlap');
	await v.get('zapret2-profiles-apply').attrs.click();
	await v.get('zapret2-save').attrs.click();
	assert.equal(h.calls.find(c => c.method === 'configure').args.length, 6);
	assert.equal(h.state.profile_id, 'overlap');
	assert.equal(text(v.get('zapret2-active-profile')), 'Разделение с перекрытием · overlap');
});

test('stale main polling cannot overwrite newly applied saved profile or report its stale failure', async () => {
	for (const failed of [false, true]) {
		const h = harness(), v = await h.render(); candidate(v);
		let finish;
		h.handlers.status = () => new Promise((resolve, reject) => { finish = failed ? reject : resolve; });
		const polling = h.pollers[0].callback(); await Promise.resolve();
		h.handlers.status = () => ({ ...h.state });
		await v.get('zapret2-profiles-apply').attrs.click();
		finish(failed ? new Error('stale failure') : { ...h.state, profile_id: 'alt1' }); await polling;
		assert.equal(text(v.get('zapret2-active-profile')), 'Базовый · stock');
		assert.equal(text(v.get('zapret2-message')), '');
	}
});

test('catalog metadata cannot inject controls/URLs or replace fixed IDs', async () => {
	const catalog = protocolCatalog(structuredClone(profilesCatalog));
	for (const item of catalog.groups.flatMap(g => [...g.profiles, ...g.targets])) Object.assign(item, { title: injected, strategy: injected, description: injected, url: 'javascript:alert(1)' });
	const h = harness({ protocols_catalog: () => ({ ok: true, catalog }), protocols_status: () => ({ ok: true, catalog, data: { state: 'idle', running: false, results: [] } }) }), v = await h.render();
	candidate(v); await v.get('zapret2-profiles-apply').attrs.click();
	assert.deepEqual(h.calls.find(c => c.method === 'protocols_apply').args, ['tcp', true, 'stock']);
	assert.ok(!v.all.some(n => ['img', 'script', 'a'].includes(n.tag)));
});

test('matrix distinguishes full_match, HTTP-only failure, mixed repeats, missing rows and untested services', async () => {
	const h = harness(), v = await h.render();
	chooseProfiles(v, ['alt1', 'stock', 'overlap'], ['gitlab', 'unitask']);
	v.get('zapret2-test-repeat').value = '2';
	await v.get('zapret2-profiles-start').attrs.click();
	assert.equal(v.get('zapret2-result-alt1-gitlab').attrs['data-result'], 'pending');
	assert.equal(v.get('zapret2-result-alt1-youtube').attrs['data-result'], 'untested');
	Object.assign(h.profilesState, { state: 'results', running: false, results: [
		profileRow(), profileRow({ repeat: 2 }),
		profileRow({ target: 'unitask' }), profileRow({ target: 'unitask', repeat: 2, full_match: false, failure: 'body' }),
		profileRow({ profile: 'stock', full_match: false, failure: 'body', status: 200 }),
		profileRow({ profile: 'overlap' })
	] });
	await h.pollers[1].callback();
	for (const [id, kind] of [['alt1-gitlab', 'success'], ['alt1-unitask', 'mixed'], ['stock-gitlab', 'failure'], ['overlap-gitlab', 'partial'], ['stock-unitask', 'missing']])
		assert.equal(v.get('zapret2-result-' + id).attrs['data-result'], kind, id);
	assert.match(text(v.get('zapret2-result-alt1-unitask')), /Смешанный.*1\/2/);
	assert.match(text(v.get('zapret2-result-overlap-gitlab')), /нет части попыток/);
	assert.match(text(v.get('zapret2-result-summary-alt1')), /Полностью: 1\/2/);
	assert.match(text(v.get('zapret2-result-summary-alt1')), /Смешано: 1/);
	assert.match(text(v.get('zapret2-result-summary-stock')), /Не завершено: 2/);
	assert.match(text(v.get('zapret2-result-summary-stock')), /Полностью: 0\/2/);
	assert.match(text(v.get('zapret2-profiles-state')), /6\/12/);
	assert.doesNotMatch(text(v.get('zapret2-profiles-results')), /HTTP|full_match|connect_or_setup|быстр|победител/i);
});

test('completed matrix and progress stay bound to the last acknowledged plan after editing selections', async () => {
	const h = harness(), v = await h.render(); chooseProfiles(v, ['alt1'], ['gitlab']);
	v.get('zapret2-test-repeat').value = '2'; await v.get('zapret2-profiles-start').attrs.click();
	Object.assign(h.profilesState, { state: 'results', running: false, results: [profileRow()] }); await h.pollers[1].callback();
	const before = text(v.get('zapret2-profiles-results'));
	chooseProfiles(v, ['stock', 'fake'], ['youtube', 'discord']);
	v.get('zapret2-test-repeat').value = '1'; v.get('zapret2-test-repeat').attrs.change();
	await h.pollers[0].callback();
	assert.equal(text(v.get('zapret2-profiles-results')), before);
	assert.match(text(v.get('zapret2-profiles-state')), /1\/2/);
	assert.equal(v.get('zapret2-result-stock-youtube').attrs['data-result'], 'untested');
	assert.match(text(v.get('zapret2-test-plan')), /= 4 проверок/);
});

test('cleanup with collected results never claims completed, and duplicate attempts are counted conservatively', async () => {
	const h = harness(), v = await h.render(); chooseProfiles(v, ['alt1'], ['gitlab']);
	await v.get('zapret2-profiles-start').attrs.click();
	Object.assign(h.profilesState, { state: 'results', running: true, results: [profileRow(), profileRow({ full_match: false, failure: 'body' })] });
	await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-state')), /Результаты получены.*1\/1.*завершение не подтверждено/);
	assert.doesNotMatch(text(v.get('zapret2-profiles-state')), /Тест завершён/);
	assert.equal(v.get('zapret2-result-alt1-gitlab').attrs['data-result'], 'failure');
	assert.equal(v.get('zapret2-profiles-apply').disabled, true);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	assert.match(text(v.get('zapret2-profiles-technical')), /Задание:.*\n.*HTTP 200.*\nСтратегия:/);
	Object.assign(h.profilesState, { running: false, results: [profileRow({ repeat: 2 })] });
	await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-state')), /0\/1/);
	assert.equal(v.get('zapret2-result-alt1-gitlab').attrs['data-result'], 'missing');
});

test('loaded history without captured job plan cannot claim complete coverage', async () => {
	const h = harness(); Object.assign(h.profilesState, { state: 'results', job_id: '999.111', results: [profileRow()] });
	const v = await h.render();
	assert.match(text(v.get('zapret2-profiles-state')), /план запуска неизвестен/);
	assert.equal(v.get('zapret2-result-alt1-gitlab').attrs['data-result'], 'partial');
	assert.match(text(v.get('zapret2-result-summary-alt1')), /Проверено сервисов: 1\/5/);
	assert.equal(nodes(v.get('zapret2-profiles-results')).filter(n => n.attrs['data-result'] === 'success').length, 0);
});

test('comparison has no selection controls or handlers; only manual selector and explicit Apply write', async () => {
	const h = harness(); Object.assign(h.profilesState, { state: 'results', results: [profileRow({ profile: 'stock' })] });
	const v = await h.render(), before = h.calls.length;
	assert.ok(nodes(v.get('zapret2-profiles-results')).every(n => !['button', 'select', 'input'].includes(n.tag) && !n.attrs.click && !n.attrs.change));
	assert.equal(v.get('zapret2-result-select-stock'), undefined);
	assert.equal(nodes(h.tabGroups[0][3]).filter(n => n.tag === 'select' && n.attrs.id === 'zapret2-apply-profile').length, 1);
	candidate(v);
	assert.equal(h.calls.length, before);
	assert.equal(text(v.get('zapret2-active-profile')), 'Основной · alt1');
	await v.get('zapret2-profiles-apply').attrs.click();
	assert.deepEqual(h.calls.find(c => c.method === 'protocols_apply').args, ['tcp', true, 'stock']);
});

test('native progress counts accepted unique attempts, separates 100% checks from cleanup and terminal completion', async () => {
	const h = harness(), v = await h.render(); chooseProfiles(v, ['alt1'], ['gitlab']);
	v.get('zapret2-test-repeat').value = '2'; await v.get('zapret2-profiles-start').attrs.click();
	const bar = v.get('zapret2-profiles-progress');
	assert.equal(bar.tag, 'progress'); assert.equal(bar.value, 0); assert.equal(bar.max, 2);
	assert.match(text(v.get('zapret2-profiles-state')), /0\/2.*0%/);
	Object.assign(h.profilesState, { state: 'running', running: true, results: [profileRow(), profileRow(), profileRow({ profile: 'stock' })] });
	await h.pollers[1].callback(); assert.equal(bar.value, 1);
	assert.match(text(v.get('zapret2-profiles-state')), /1\/2.*50%/);
	h.profilesState.results = [profileRow(), profileRow({ repeat: 2 }), profileRow({ repeat: 2 })];
	await h.pollers[1].callback(); assert.equal(bar.value, 2);
	assert.match(text(v.get('zapret2-profiles-state')), /100%.*очистка/i);
	assert.doesNotMatch(text(v.get('zapret2-profiles-state')), /Тест завершён/);
	h.profilesState.state = 'results';
	await h.pollers[1].callback(); assert.equal(bar.value, 2);
	assert.match(text(v.get('zapret2-profiles-state')), /2\/2.*100%.*очистка/i);
	assert.doesNotMatch(text(v.get('zapret2-profiles-state')), /Тест завершён/);
	assert.equal(v.get('zapret2-profiles-apply').disabled, true);
	h.profilesState.running = false; await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-state')), /Тест завершён/);
	assert.equal(text(v.get('zapret2-result-summary-alt1')), 'Полностью: 1/1');
	assert.equal(v.get('zapret2-profiles-progress'), bar);
});

test('unknown or malformed progress is indeterminate with last known counts; history never invents attempt totals', async () => {
	const h = harness(), v = await h.render(); await v.get('zapret2-profiles-start').attrs.click();
	Object.assign(h.profilesState, { state: 'running', results: [profileRow()] }); await h.pollers[1].callback();
	for (const handler of [() => { throw new Error('lost'); }, () => ({ ok: true, catalog: protocolCatalog(profilesCatalog), data: { ...h.profilesState, running: 'false' } })]) {
		h.handlers.protocols_status = handler; await h.pollers[1].callback();
		assert.equal(v.get('zapret2-profiles-progress').attrs.value, undefined);
		assert.match(text(v.get('zapret2-profiles-state')), /неизвестен.*Последние данные:.*1\/6/);
		assert.doesNotMatch(text(v.get('zapret2-profiles-state')), /Тест завершён/);
	}
	const history = harness(); Object.assign(history.profilesState, { state: 'results', results: [profileRow()] });
	const loaded = await history.render();
	assert.equal(loaded.get('zapret2-profiles-progress').attrs.value, undefined);
	assert.match(text(loaded.get('zapret2-profiles-state')), /план запуска неизвестен/);
	assert.doesNotMatch(text(loaded.get('zapret2-profiles-state')), /%|1\/1/);
});

test('launching is indeterminate until acknowledgment and error stage never claims successful completion', async () => {
	const h = harness(), v = await h.render();
	let release; h.handlers.protocols_test = () => new Promise(resolve => { release = resolve; });
	const launching = v.get('zapret2-profiles-start').attrs.click();
	for (let i = 0; i < 20 && !release; i++) await Promise.resolve();
	assert.equal(typeof release, 'function');
	assert.match(text(v.get('zapret2-profiles-state')), /Запуск теста/);
	assert.equal(v.get('zapret2-profiles-progress').attrs.value, undefined);
	Object.assign(h.profilesState, { state: 'running', running: true, job_id: '123.456', results: [] });
	release({ ok: true, pending: true, job_id: '123.456' }); await launching;
	assert.equal(v.get('zapret2-profiles-progress').value, 0);
	Object.assign(h.profilesState, { state: 'error', running: true, error: injected, results: [profileRow()] }); await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-state')), /Ошибка теста.*1\/6/);
	assert.doesNotMatch(text(v.get('zapret2-profiles-state')), /Тест завершён/);
	assert.equal(v.get('zapret2-profiles-start').disabled, true);
	h.profilesState.running = false; await h.pollers[1].callback();
	assert.match(text(v.get('zapret2-profiles-state')), /Ошибка теста/);
	assert.equal(v.get('zapret2-profiles-progress').value, 1);
});

test('practical defaults never auto-start and polling never restores cleared user choices', async () => {
	const h = harness(), v = await h.render();
	assert.match(text(v.get('zapret2-test-plan')), /2 профиля × 3 сервиса × 1 = 6 проверок/);
	assert.match(text(v.get('zapret2-saved-profile-hint')), /остановлена.*сохранённый профиль/);
	v.get('zapret2-test-profile-clear').attrs.click();
	assert.match(text(v.get('zapret2-test-hint')), /Выберите хотя бы/);
	await h.pollers[0].callback(); await h.pollers[1].callback();
	assert.ok(profileIds.every(id => !v.get('zapret2-test-profile-' + id).checked));
	assert.ok(!h.calls.some(c => ['protocols_test', 'protocols_apply'].includes(c.method)));
	for (const detail of nodes(h.tabGroups[0][3]).filter(n => n.tag === 'details')) assert.ok(!detail.attrs.open);
});

test('an in-flight diagnostic poll resolves independently of normal settings save', async () => {
	for (const failed of [false, true]) {
		const h = harness(); Object.assign(h.profilesState, { state: 'running', running: true, job_id: '111.222' });
		const v = await h.render(); let finish;
		h.handlers.protocols_status = () => new Promise((resolve, reject) => { finish = failed ? reject : resolve; });
		const polling = h.pollers[1].callback(); await Promise.resolve();
		// Main save may complete while the isolated status request is in flight; apply remains locked.
		await v.get('zapret2-save').attrs.click();
		finish(failed ? new Error('old diagnostic error') : { ok: true, catalog: protocolCatalog(profilesCatalog), data: { protocol: 'tcp', state: 'results', running: false, job_id: '111.222', results: [profileRow()] } });
		await polling;
		assert.equal(v.get('zapret2-save').disabled, false);
		assert.equal(v.get('zapret2-profiles-start').disabled, failed);
	}
});

test('unchanged progress poll preserves matrix nodes and does not rewrite the live-region text', async () => {
	const h = harness(), v = await h.render(); await v.get('zapret2-profiles-start').attrs.click();
	const matrixCell = v.get('zapret2-result-alt1-gitlab'), message = v.get('zapret2-profiles-state');
	let writes = 0, value = message.textContent;
	Object.defineProperty(message, 'textContent', { get: () => value, set: next => { writes++; value = next; } });
	const bar = v.get('zapret2-profiles-progress'); let barWrites = 0;
	for (const key of ['value', 'max']) { let stored = bar[key]; Object.defineProperty(bar, key, { get: () => stored, set: next => { barWrites++; stored = next; } }); }
	await h.pollers[1].callback(); await h.pollers[1].callback();
	assert.equal(writes, 0);
	assert.equal(barWrites, 0); assert.equal(v.get('zapret2-profiles-progress'), bar);
	assert.equal(v.get('zapret2-result-alt1-gitlab'), matrixCell);
});

test('menu and ACL expose only scoped zapret2_home operations', () => {
	const menu = JSON.parse(fs.readFileSync(path.join(root, 'files/usr/share/luci/menu.d/luci-app-zapret2-home.json')));
	assert.deepEqual(menu['admin/services/zapret2home'].action, { type: 'view', path: 'services/zapret2home' });
	assert.deepEqual(menu['admin/services/zapret2home'].depends.acl, ['luci-app-zapret2-home']);
	const acl = JSON.parse(fs.readFileSync(path.join(root, 'files/usr/share/rpcd/acl.d/luci-app-zapret2-home.json')));
	const grant = acl['luci-app-zapret2-home'];
	assert.deepEqual(grant.read, { ubus: { zapret2_home: ['status', 'logs', 'check', 'profiles_catalog', 'profiles_status', 'protocols_catalog', 'protocols_status'] } });
	assert.deepEqual(grant.write, { ubus: { zapret2_home: ['configure', 'control', 'update_lists', 'profiles_test', 'profiles_apply', 'protocols_test', 'protocols_apply'] } });
});


function branch(v, protocol, name) { return v.get('zapret2-' + (protocol === 'tcp' ? '' : protocol + '-') + name); }
function stageBranch(v, protocol, enabled, profile) {
 const select = branch(v, protocol, 'apply-profile');
 select.value = enabled ? profile || select.children.find(option => option.attrs.value)?.attrs.value || '' : '';
 select.attrs.change();
}
test('each protocol has one saved-choice selector: Off plus six fixed profiles, no enable checkbox', async () => {
 const h = harness(), v = await h.render();
 assert.doesNotMatch(text(h.tabGroups[0][3]), /ветк/i);
 for (const group of protocolCatalog(profilesCatalog).groups) {
  const select = branch(v, group.id, 'apply-profile'), saved = h.state.protocols[group.id];
  assert.equal(branch(v, group.id, 'branch-enabled'), undefined);
  assert.equal(select.value, saved.enabled ? saved.profile : '');
  assert.deepEqual(select.children.map(option => option.attrs.value), ['', ...group.profiles.map(p => p.id)]);
  assert.equal(text(select.children[0]), 'Выключено');
  assert.equal(branch(v, group.id, 'profiles-apply').disabled, true);
  assert.match(text(branch(v, group.id, 'apply-hint')), /уже сохранён/);
  await branch(v, group.id, 'profiles-apply').attrs.click();
 }
 assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
});
test('every fixed profile enables and disables its protocol with retained backend ID and unchanged other settings', async () => {
 for (const group of protocolCatalog(profilesCatalog).groups) {
  const h = harness(); h.state.running = true;
  if (group.id === 'tcp') h.state.protocols.udp.enabled = true;
  h.state.protocols[group.id].enabled = false;
  const v = await h.render(), others = JSON.stringify(Object.entries(h.state.protocols).filter(([id]) => id !== group.id));
  for (const item of group.profiles) {
   stageBranch(v, group.id, true, item.id);
   await branch(v, group.id, 'profiles-apply').attrs.click();
   assert.deepEqual(h.calls.filter(c => c.method === 'protocols_apply').at(-1).args, [group.id, true, item.id]);
   assert.equal(text(v.get('zapret2-message')), '');
   assert.equal(branch(v, group.id, 'profiles-apply').disabled, true, 'Same enabled profile is a no-op');
   stageBranch(v, group.id, false);
   await branch(v, group.id, 'profiles-apply').attrs.click();
   assert.deepEqual(h.calls.filter(c => c.method === 'protocols_apply').at(-1).args, [group.id, false, item.id]);
   assert.equal(h.state.protocols[group.id].profile, item.id, 'Off retains last ID, never sends empty backend profile');
   assert.equal(h.state.protocols[group.id].enabled, false);
   assert.equal(branch(v, group.id, 'apply-profile').value, '');
   assert.equal(text(branch(v, group.id, 'active-profile')), 'Выключено');
   assert.equal(branch(v, group.id, 'profiles-apply').disabled, true, 'Same disabled state is a no-op');
   assert.equal(text(v.get('zapret2-message')), '');
   assert.equal(JSON.stringify(Object.entries(h.state.protocols).filter(([id]) => id !== group.id)), others);
  }
  assert.equal(h.calls.filter(c => c.method === 'protocols_apply').length, 12);
  assert.equal(h.state.running, true);
  assert.ok(!h.calls.some(c => ['control', 'configure'].includes(c.method)));
 }
});
test('independent protocol summaries come from confirmed saved state, not assumed defaults', async () => {
 const h = harness(), v = await h.render();
 assert.match(text(v.get('zapret2-summary-tcp')), /Включён.*alt1/);
 for (const id of ['quic', 'udp']) assert.match(text(v.get('zapret2-summary-' + id)), /Выключен/);
 assert.match(text(v.get('zapret2-protocol-saved-state')), /остановлена/);
 h.state.running = true; h.state.protocols.quic = { enabled: true, profile: 'quic_zero' }; await h.pollers[0].callback();
 assert.match(text(v.get('zapret2-summary-quic')), /Включён.*quic_zero/);
 assert.match(text(v.get('zapret2-protocol-saved-state')), /не подтверждена/);
 delete h.state.protocols; await h.pollers[0].callback();
 for (const id of ['tcp', 'quic', 'udp']) {
  assert.match(text(v.get('zapret2-summary-' + id)), /Неизвестно/);
  assert.equal(branch(v, id, 'apply-profile').disabled, true);
  assert.equal(branch(v, id, 'profiles-apply').disabled, true);
 }
});
test('protocol navigation and staged enable/profile preserve all choices without RPC writes', async () => {
 const h = harness(), v = await h.render(), before = h.calls.length;
 stageBranch(v, 'quic', true, 'quic_zero'); stageBranch(v, 'udp', true, 'udp_fake6'); candidate(v, 'stock');
 for (const id of ['quic', 'udp', 'tcp', 'quic']) v.get('zapret2-protocol-' + id).attrs.click();
 assert.equal(h.calls.length, before);
 assert.equal(branch(v, 'quic', 'apply-profile').value, 'quic_zero');
 assert.equal(v.get('zapret2-protocol-quic').attrs['aria-pressed'], 'true');
 assert.equal(v.get('zapret2-quic-protocol-panel').hidden, false);
 assert.equal(v.get('zapret2-udp-protocol-panel').hidden, true);
 await h.pollers[0].callback();
 for (const id of ['quic', 'udp']) { assert.notEqual(branch(v, id, 'apply-profile').value, ''); assert.match(text(v.get('zapret2-summary-' + id)), /Выключен/); assert.match(text(branch(v, id, 'apply-hint')), /Не сохранено/); }
 assert.equal(v.get('zapret2-apply-profile').value, 'stock');
});
test('unsupported HTTP3 disables only QUIC testing, explains why, permits explicit experimental apply', async () => {
 const catalog = protocolCatalog(profilesCatalog); Object.assign(catalog.groups[1], { test_supported: false, test_unavailable_reason: 'Тест недоступен: curl не поддерживает HTTP3.' });
 const h = harness({ protocols_catalog: () => ({ ok: true, catalog }) }), v = await h.render();
 assert.equal(branch(v, 'quic', 'profiles-start').disabled, true);
 assert.match(text(branch(v, 'quic', 'test-hint')), /curl.*HTTP3/);
 assert.match(text(v.get('zapret2-quic-protocol-panel')), /HTTP3, НЕ видео/);
 stageBranch(v, 'quic', true, 'quic_google');
 assert.equal(branch(v, 'quic', 'profiles-apply').disabled, false);
 await branch(v, 'quic', 'profiles-start').attrs.click();
 await branch(v, 'quic', 'profiles-apply').attrs.click();
 assert.deepEqual(h.calls.find(c => c.method === 'protocols_apply').args, ['quic', true, 'quic_google']);
 assert.ok(!h.calls.some(c => c.method === 'protocols_test'));
 assert.deepEqual(h.state.protocols.udp, { enabled: false, profile: 'udp_fake2' });
 assert.equal(h.state.profile_id, 'alt1'); assert.equal(h.state.running, false);
 assert.equal(text(v.get('zapret2-message')), '');
});
test('per-branch disable preserves its selected profile and other active branches, never calls global stop', async () => {
 const h = harness(); h.state.running = true; h.state.protocols.udp.enabled = true;
 const v = await h.render(); stageBranch(v, 'tcp', false);
 assert.equal(v.get('zapret2-apply-profile').value, '', 'Empty selection means disabled, not unset');
 await branch(v, 'tcp', 'profiles-apply').attrs.click();
 assert.equal(h.state.protocols.tcp.enabled, false); assert.equal(h.state.profile_id, 'alt1');
 assert.equal(h.state.protocols.udp.enabled, true); assert.equal(h.state.running, true);
 assert.ok(!h.calls.some(c => c.method === 'control'));
});
test('last enabled branch cannot be disabled, including stale preflight state; Stop remains global', async () => {
 const h = harness(); h.state.running = true; const v = await h.render();
 stageBranch(v, 'tcp', false); assert.equal(branch(v, 'tcp', 'profiles-apply').disabled, true);
 assert.match(text(branch(v, 'tcp', 'apply-hint')), /Остановить всё/);
 await branch(v, 'tcp', 'profiles-apply').attrs.click(); assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
 h.state.protocols.udp.enabled = true; await h.pollers[0].callback();
 assert.equal(branch(v, 'tcp', 'profiles-apply').disabled, false);
 h.state.protocols.udp.enabled = false; await branch(v, 'tcp', 'profiles-apply').attrs.click();
 assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
 await v.get('zapret2-stop').attrs.click(); assert.equal(h.state.running, false);
 assert.equal(h.state.protocols.tcp.enabled, true); assert.equal(h.state.protocols.udp.enabled, false);
});
test('UDP strict STUN diagnostics use their own IDs, dynamic matrix and acknowledged plan', async () => {
 const h = harness(), v = await h.render();
 await branch(v, 'udp', 'profiles-start').attrs.click();
 assert.deepEqual(h.calls.find(c => c.method === 'protocols_test').args, ['udp', 'udp_fake2 udp_fake6 udp_protocol_fake2 udp_badsum2 udp_ttl2 udp_protocol_badsum2', 'stun_google', 1]);
 assert.match(text(branch(v, 'udp', 'profiles-state')), /0\/6/);
 assert.equal(branch(v, 'quic', 'profiles-apply').disabled, true);
 Object.assign(h.profilesState, { protocol: 'udp', state: 'results', running: false, results: [
  { protocol: 'udp', profile: 'udp_fake2', target: 'stun_google', repeat: 1, full_match: true, failure: '' },
  { protocol: 'udp', profile: 'udp_fake6', target: 'stun_google', repeat: 1, full_match: false, failure: 'stun_transaction' }
 ] }); await h.pollers[1].callback();
 assert.match(text(branch(v, 'udp', 'profiles-state')), /2\/6/);
 assert.equal(branch(v, 'udp', 'result-udp_fake2-stun_google').attrs['data-result'], 'success');
 assert.match(text(branch(v, 'udp', 'profiles-results')), /строгих STUN/);
 assert.match(text(branch(v, 'udp', 'profiles-technical')), /Строгий STUN-ответ, не голос/);
 assert.doesNotMatch(text(branch(v, 'udp', 'profiles-technical')), /undefined|HTTP/);
 assert.doesNotMatch(text(branch(v, 'tcp', 'profiles-results')), /udp_fake/);
 assert.match(text(v.get('zapret2-udp-protocol-panel')), /вручную с собеседником/);
 assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
});
test('QUIC supported diagnostic is explicit HTTP3, never TCP IDs or whole-video proof', async () => {
 const catalog = protocolCatalog(profilesCatalog); catalog.groups[1].test_supported = true; catalog.groups[1].test_unavailable_reason = '';
 const h = harness({ protocols_catalog: () => ({ ok: true, catalog }) }), v = await h.render();
 await branch(v, 'quic', 'profiles-start').attrs.click();
 assert.deepEqual(h.calls.find(c => c.method === 'protocols_test').args, ['quic', 'quic_google quic_zero quic_google_badsum quic_google_ttl2 quic_zero_badsum quic_zero_ttl2', 'youtube_h3', 1]);
 h.profilesState.state = 'results'; h.profilesState.running = false;
 h.profilesState.results = [profileRow({ protocol: 'quic', profile: 'quic_google', target: 'youtube_h3', http_version: '3' })];
 await h.pollers[1].callback();
 assert.match(text(branch(v, 'quic', 'profiles-results')), /HTTP\/3, не видео/);
 assert.equal(branch(v, 'quic', 'result-quic_google-youtube_h3').attrs['data-result'], 'success');
 assert.equal(branch(v, 'quic', 'result-quic_zero-youtube_h3').attrs['data-result'], 'missing');
 assert.equal(branch(v, 'quic', 'apply-profile').value, '');
});
test('cross-protocol rows and same-job wrong protocol fail closed without painting another matrix', async () => {
 for (const wrong of ['row', 'state']) {
  const h = harness(), v = await h.render(); await branch(v, 'udp', 'profiles-start').attrs.click();
  Object.assign(h.profilesState, { protocol: wrong === 'state' ? 'tcp' : 'udp', state: 'results', running: false, results: wrong === 'row' ? [profileRow()] : [] });
  await h.pollers[1].callback();
  assert.equal(branch(v, 'udp', 'profiles-start').disabled, true);
  assert.equal(branch(v, 'udp', 'profiles-progress').attrs.value, undefined);
  assert.doesNotMatch(text(branch(v, 'tcp', 'profiles-results')), /✓/);
  assert.match(text(branch(v, 'udp', 'profiles-state')), /Ошибка/);
 }
});
test('selected branch apply requires enabled AND profile readback plus matching terminal configure job', async () => {
 for (const fault of ['enabled', 'profile', 'job', 'result']) {
  const h = harness(), v = await h.render(); stageBranch(v, 'udp', true, 'udp_fake6');
  h.handlers.protocols_apply = () => {
   h.state.protocols.udp = { enabled: fault !== 'enabled', profile: fault === 'profile' ? 'udp_fake2' : 'udp_fake6' };
   Object.assign(h.state, { configure_pending: false, configure_job_id: fault === 'job' ? 999 : 901, configure_result: { job_id: fault === 'result' ? 999 : 901, ok: true } });
   return { ok: true, pending: true, job_id: 901 };
  };
  await branch(v, 'udp', 'profiles-apply').attrs.click();
  assert.match(text(v.get('zapret2-message')), /Ошибка/);
  assert.equal(h.state.profile_id, 'alt1');
 }
});
test('missing lifecycle flags block protocol writes initially and at preflight without losing selections', async () => {
 for (const key of ['configure_pending', 'configure_recovery_required', 'update_running']) for (const preflight of [false, true]) {
  const h = harness();
  if (!preflight) delete h.state[key];
  const v = await h.render();
  stageBranch(v, 'udp', true, 'udp_fake6');
  if (preflight) delete h.state[key];
  else for (const id of ['tcp', 'quic', 'udp']) assert.equal(branch(v, id, 'profiles-apply').disabled, true, key);
  await branch(v, 'udp', 'profiles-apply').attrs.click();
  await branch(v, 'udp', 'profiles-start').attrs.click();
  assert.ok(!h.calls.some(c => ['protocols_apply', 'protocols_test'].includes(c.method)), key);
  assert.equal(branch(v, 'udp', 'apply-profile').value, 'udp_fake6');
  for (const id of ['tcp', 'quic', 'udp']) assert.equal(branch(v, id, 'profiles-apply').disabled, true, key);
 }
});
test('successful protocol commit is confirmed even when an independent list update starts before final readback', async () => {
 for (const pending of [false, true]) {
  const h = harness(), v = await h.render(); stageBranch(v, 'udp', true, 'udp_fake6');
  let applied = false, reads = 0;
  h.handlers.protocols_apply = () => {
   applied = true;
   h.state.protocols.udp = { enabled: true, profile: 'udp_fake6' };
   Object.assign(h.state, { configure_pending: false, configure_recovery_required: false, configure_job_id: '21326', configure_result: { ok: true, job_id: '21326' } });
   return { ok: true, pending, job_id: '21326' };
  };
  h.handlers.status = () => {
   if (applied && ++reads === (pending ? 2 : 1)) h.state.update_running = true;
   return { ...h.state };
  };
  await branch(v, 'udp', 'profiles-apply').attrs.click();
  assert.equal(text(v.get('zapret2-message')), '', 'Exact successful job must not be rejected by later list update (pending=' + pending + ')');
  assert.equal(h.state.update_running, true);
  assert.equal(branch(v, 'udp', 'profiles-apply').disabled, true, 'Updater still blocks subsequent writes');
  assert.equal(h.calls.filter(c => c.method === 'protocols_apply').length, 1);
 }
});

test('fast and pending apply reject lost, malformed, incomplete and changed final status after exact job completion', async () => {
 for (const pending of [false, true]) for (const fault of ['lost', 'malformed', 'missing-other-protocol', 'unknown-profile', 'invalid-enabled', 'recovery', 'missing-recovery', 'job', 'result', 'failed-result', 'missing-result', 'pending']) {
  const h = harness(), v = await h.render(); stageBranch(v, 'udp', true, 'udp_fake6');
  let applied = false, reads = 0;
  h.handlers.protocols_apply = () => {
   applied = true;
   h.state.protocols.udp = { enabled: true, profile: 'udp_fake6' };
   Object.assign(h.state, { configure_pending: false, configure_recovery_required: false, configure_job_id: '21326', configure_result: { ok: true, job_id: '21326' } });
   return { ok: true, pending, job_id: '21326' };
  };
  h.handlers.status = () => {
   if (applied && ++reads === (pending ? 2 : 1)) {
    if (fault === 'lost') throw new Error('Final status unavailable');
    if (fault === 'malformed') return { ...h.state, running: 'false' };
    if (fault === 'missing-other-protocol') delete h.state.protocols.quic;
    if (fault === 'unknown-profile') h.state.protocols.udp.profile = 'unknown';
    if (fault === 'invalid-enabled') h.state.protocols.udp.enabled = 'true';
    if (fault === 'recovery') h.state.configure_recovery_required = true;
    if (fault === 'missing-recovery') delete h.state.configure_recovery_required;
    if (fault === 'job') h.state.configure_job_id = '21327';
    if (fault === 'result') h.state.configure_result.job_id = '21327';
    if (fault === 'failed-result') h.state.configure_result.ok = false;
    if (fault === 'missing-result') delete h.state.configure_result;
    if (fault === 'pending') h.state.configure_pending = true;
   }
   return { ...h.state };
  };
  await branch(v, 'udp', 'profiles-apply').attrs.click();
  assert.match(text(v.get('zapret2-message')), /Ошибка/, pending + '/' + fault);
  assert.equal(h.calls.filter(c => c.method === 'protocols_apply').length, 1);
  if (['lost', 'malformed', 'missing-other-protocol', 'unknown-profile', 'invalid-enabled', 'recovery', 'missing-recovery', 'pending'].includes(fault))
   for (const protocol of ['tcp', 'quic', 'udp']) assert.equal(branch(v, protocol, 'profiles-apply').disabled, true);
 }
});
test('fast terminal protocol apply requires its exact successful job, not just matching branch values', async () => {
 for (const fault of ['none', 'job', 'result', 'failed', 'missing', 'pending', 'no-ack']) {
  const h = harness(), v = await h.render(); stageBranch(v, 'udp', true, 'udp_fake6');
  h.handlers.protocols_apply = () => {
   h.state.protocols.udp = { enabled: true, profile: 'udp_fake6' };
   Object.assign(h.state, { configure_pending: fault === 'pending', configure_job_id: fault === 'job' ? 902 : 901,
    configure_result: fault === 'missing' ? null : { job_id: fault === 'result' ? 902 : 901, ok: fault !== 'failed' } });
   return fault === 'no-ack' ? { ok: true } : { ok: true, job_id: 901 };
  };
  await branch(v, 'udp', 'profiles-apply').attrs.click();
  if (fault === 'none') assert.doesNotMatch(text(v.get('zapret2-message')), /Ошибка/, fault);
  else assert.match(text(v.get('zapret2-message')), /Ошибка/, fault);
 }
});
test('unknown, recovery, updater and diagnostic cleanup lock every protocol write without losing staged values', async () => {
 const h = harness(), v = await h.render(); stageBranch(v, 'quic', true, 'quic_zero'); stageBranch(v, 'udp', true, 'udp_fake6');
 for (const key of ['configure_pending', 'configure_recovery_required', 'update_running']) {
  h.state[key] = true; await h.pollers[0].callback();
  for (const id of ['tcp', 'quic', 'udp']) assert.equal(branch(v, id, 'profiles-apply').disabled, true);
  h.state[key] = false; await h.pollers[0].callback();
 }
 Object.assign(h.profilesState, { protocol: 'udp', state: 'error', running: true, error: 'Cleanup failed' });
 await branch(v, 'udp', 'profiles-apply').attrs.click();
 assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
 for (const id of ['tcp', 'quic', 'udp']) assert.equal(branch(v, id, 'profiles-apply').disabled, true);
 assert.equal(branch(v, 'quic', 'apply-profile').value, 'quic_zero');
 assert.equal(branch(v, 'udp', 'apply-profile').value, 'udp_fake6');
});
test('protocol catalog trust boundary rejects duplicates, cross IDs and missing capabilities', async () => {
 for (const mutate of [c => c.groups.reverse(), c => c.groups[1].profiles.push(c.groups[1].profiles[0]), c => c.groups[2].profiles[0].id = 'alt1', c => delete c.groups[0].test_supported, c => { c.groups[1].test_supported = false; c.groups[1].test_unavailable_reason = ''; }, c => c.groups[2].targets[0].id = 'youtube_h3']) {
  const catalog = protocolCatalog(profilesCatalog); mutate(catalog);
  const h = harness({ protocols_catalog: () => ({ ok: true, catalog }) }), v = await h.render();
  for (const id of ['tcp', 'quic', 'udp']) { stageBranch(v, id, true); assert.equal(branch(v, id, 'profiles-apply').disabled, true); assert.equal(branch(v, id, 'profiles-start').disabled, true); }
  assert.match(text(v.tree), /Обновите пакет|обновите пакет/);
 }
});
test('catalog counts and loaded plan are dynamic per protocol, never six profiles or five targets by assumption', async () => {
 const catalog = protocolCatalog(profilesCatalog); catalog.groups[2].profiles = catalog.groups[2].profiles.slice(0, 1);
 const h = harness({ protocols_catalog: () => ({ ok: true, catalog }) });
 Object.assign(h.profilesState, { protocol: 'udp', state: 'results', running: false, job_id: '321.654', plan: { protocol: 'udp', profiles: ['udp_fake2'], targets: ['stun_google'], repeat: 1 }, results: [{ protocol: 'udp', profile: 'udp_fake2', target: 'stun_google', repeat: 1, full_match: true, failure: '' }] });
 const v = await h.render();
 assert.match(text(branch(v, 'udp', 'test-plan')), /1.*× 1.*= 1/);
 assert.match(text(branch(v, 'udp', 'profiles-state')), /1\/1.*100%/);
 assert.equal(nodes(branch(v, 'udp', 'profiles-results')).filter(n => n.tag === 'td').length, 1);
 assert.match(text(branch(v, 'udp', 'result-summary-udp_fake2')), /1\/1/);
});
test('all protocol inputs have unique IDs and explicit accessible labels; technical panels remain collapsed', async () => {
 const h = harness(), v = await h.render();
 const ids = v.all.map(n => n.attrs.id).filter(Boolean); assert.equal(new Set(ids).size, ids.length);
 for (const n of nodes(h.tabGroups[0][3]).filter(n => n.tag === 'input' || n.tag === 'select')) assert.ok(v.all.some(label => label.tag === 'label' && label.attrs.for === n.attrs.id), n.attrs.id);
 assert.ok(nodes(h.tabGroups[0][3]).filter(n => n.tag === 'details').every(n => !n.attrs.open));
});

test('test preflight catches newly pending main/updater state before diagnostic launch', async () => {
 for (const field of ['configure_pending', 'configure_recovery_required', 'update_running']) {
  const h = harness(), v = await h.render(); h.state[field] = true;
  await branch(v, 'udp', 'profiles-start').attrs.click();
  assert.ok(!h.calls.some(c => c.method === 'protocols_test'));
  for (const id of ['tcp', 'quic', 'udp']) assert.equal(branch(v, id, 'profiles-start').disabled, true);
 }
});
test('one unknown saved branch blocks all protocol writes with upgrade guidance', async () => {
 const h = harness(); delete h.state.protocols.quic; const v = await h.render();
 for (const id of ['tcp', 'quic', 'udp']) { assert.equal(branch(v, id, 'profiles-start').disabled, true); assert.match(text(branch(v, id, 'apply-hint')), /Обновите пакет/); }
 assert.match(text(branch(v, 'quic', 'test-hint')), /Сохранённое состояние протоколов неизвестно/);
 assert.doesNotMatch(text(branch(v, 'quic', 'test-hint')), /curl|HTTP3/);
});



test('six experimental QUIC/UDP choices select all into twelve-attempt matrices without auto-apply', async () => {
 for (const protocol of ['quic', 'udp']) {
  const h = harness(), v = await h.render(), group = protocolCatalog(profilesCatalog).groups.find(g => g.id === protocol);
  assert.equal(branch(v, protocol, 'profiles-start').disabled, false, 'Capability enables test even with saved branch OFF');
  branch(v, protocol, 'test-profile-clear').attrs.click();
  assert.equal(branch(v, protocol, 'profiles-start').disabled, true);
  branch(v, protocol, 'test-profile-all').attrs.click();
  branch(v, protocol, 'test-repeat').value = '2'; branch(v, protocol, 'test-repeat').attrs.change();
  assert.match(text(branch(v, protocol, 'test-plan')), /6.*× 1.*× 2 = 12/);
  for (const item of group.profiles) {
   const input = branch(v, protocol, 'test-profile-' + item.id);
   assert.equal(input.checked, true);
   const label = v.all.find(n => n.tag === 'label' && n.attrs.for === input.attrs.id);
   assert.match(text(label), /экспериментальный/);
   assert.match(label.attrs.title, /не являются отдельными алгоритмами/);
   if (item.id.includes('badsum')) assert.match(label.attrs.title, /неверной контрольной суммой/);
   if (item.id.includes('ttl2')) assert.match(label.attrs.title, /TTL 2/);
  }
  await branch(v, protocol, 'profiles-start').attrs.click();
  assert.deepEqual(h.calls.find(c => c.method === 'protocols_test').args, [protocol, group.profiles.map(p => p.id).join(' '), group.targets[0].id, 2]);
  Object.assign(h.profilesState, { state: 'results', running: true, results: group.profiles.flatMap(p => [1, 2].map(repeat => profileRow({ protocol, profile: p.id, target: group.targets[0].id, repeat }))) });
  await h.pollers[1].callback();
  assert.match(text(branch(v, protocol, 'profiles-state')), /12\/12.*100%.*Очистка/);
  assert.doesNotMatch(text(branch(v, protocol, 'profiles-state')), /Тест завершён/);
  assert.equal(branch(v, protocol, 'profiles-start').disabled, true);
  h.profilesState.running = false; await h.pollers[1].callback();
  assert.equal(nodes(branch(v, protocol, 'profiles-results')).filter(n => n.tag === 'td').length, 6);
  assert.equal(nodes(branch(v, protocol, 'profiles-results')).filter(n => n.attrs['data-result'] === 'success').length, 6);
  assert.ok(!nodes(branch(v, protocol, 'profiles-results')).some(n => ['button', 'select', 'input'].includes(n.tag) || n.attrs.click));
  assert.equal(branch(v, protocol, 'apply-profile').value, '');
  assert.equal(h.state.protocols[protocol].enabled, false);
  assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
 }
});


test('every new experimental variant uses explicit branch apply with exact saved readback', async () => {
 for (const protocol of ['quic', 'udp']) for (const item of protocolCatalog(profilesCatalog).groups.find(g => g.id === protocol).profiles.slice(2)) {
  const h = harness(), v = await h.render(), others = JSON.stringify(Object.entries(h.state.protocols).filter(([id]) => id !== protocol));
  stageBranch(v, protocol, true, item.id);
  assert.equal(branch(v, protocol, 'profiles-apply').disabled, false);
  assert.ok(!h.calls.some(c => c.method === 'protocols_apply'));
  await branch(v, protocol, 'profiles-apply').attrs.click();
  assert.deepEqual(h.calls.find(c => c.method === 'protocols_apply').args, [protocol, true, item.id]);
  assert.equal(h.state.protocols[protocol].enabled, true); assert.equal(h.state.protocols[protocol].profile, item.id);
  assert.equal(JSON.stringify(Object.entries(h.state.protocols).filter(([id]) => id !== protocol)), others);
  assert.match(text(v.get('zapret2-summary-' + protocol)), new RegExp('Включён.*' + item.id));
  assert.ok(!h.calls.some(c => c.method === 'configure' || c.method === 'control'));
 }
});

test('expanded protocol IDs remain fixed and malformed or legacy rows are rejected, not normalized by UI', async () => {
 for (const protocol of ['quic', 'udp']) {
  const group = protocolCatalog(profilesCatalog).groups.find(g => g.id === protocol);
  for (const change of [{ profile: group.profiles[0].id + '_unknown' }, { target: 'arbitrary' }, { protocol: 'tcp' }, { protocol: undefined }, { repeat: 3 }, { full_match: 'true' }, { failure: null }, { time_total: '1' }]) {
   const h = harness(); Object.assign(h.profilesState, { protocol, state: 'results', running: false, results: [profileRow({ protocol, profile: group.profiles[0].id, target: group.targets[0].id, ...change })] });
   const v = await h.render();
   assert.match(text(branch(v, protocol, 'profiles-state')), /Некорректный ответ/);
   for (const id of ['tcp', 'quic', 'udp']) assert.equal(branch(v, id, 'profiles-start').disabled, true);
  }
 }
});

test('updated fake_split names its tested variant and distinguishes historical results without applying it', async () => {
 const h = harness(), v = await h.render();
 const label = v.all.find(node => node.tag === 'label' && node.attrs.for === 'zapret2-test-profile-fake_split');
 assert.ok(label); assert.match(text(label), /badsum/);
 assert.match(label.attrs.title, /0\.4\.4.*badsum ×10.*1,midsld/);
 assert.match(label.attrs.title, /Прежние результаты fake_split относятся к старому варианту/);
 assert.equal(h.state.profile_id, 'alt1');
 assert.ok(!h.calls.some(call => call.method === 'protocols_apply' || call.method === 'control' || call.method === 'configure'));
});

test('unknown/prototype protocol IDs never become diagnostic capabilities', async () => {
 for (const protocol of ['constructor', '__proto__', 'toString', 'icmp']) {
  const h = harness({ protocols_status: () => ({ ok: true, data: { protocol, state: 'idle', running: false, results: [] } }) }), v = await h.render();
  for (const id of ['tcp', 'quic', 'udp']) assert.equal(branch(v, id, 'profiles-start').disabled, true);
 }
});
