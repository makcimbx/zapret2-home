'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

var callStatus = rpc.declare({ object: 'zapret2_home', method: 'status', expect: {} });
var callConfigure = rpc.declare({
	object: 'zapret2_home', method: 'configure',
	params: ['clients', 'destinations', 'autostart', 'client_mode', 'lists', 'auto_update'], expect: {}
});
var callControl = rpc.declare({ object: 'zapret2_home', method: 'control', params: ['action'], expect: {} });
var callLogs = rpc.declare({ object: 'zapret2_home', method: 'logs', expect: {} });
var callCheck = rpc.declare({ object: 'zapret2_home', method: 'check', expect: {} });
var callUpdateLists = rpc.declare({ object: 'zapret2_home', method: 'update_lists', params: [], expect: {} });
var callProfilesCatalog = rpc.declare({ object: 'zapret2_home', method: 'protocols_catalog', params: [], expect: {} });
var callProfilesStatus = rpc.declare({ object: 'zapret2_home', method: 'protocols_status', params: [], expect: {} });
var callProfilesTest = rpc.declare({ object: 'zapret2_home', method: 'protocols_test', params: ['protocol', 'profiles', 'targets', 'repeat'], expect: {} });
var callProfilesApply = rpc.declare({ object: 'zapret2_home', method: 'protocols_apply', params: ['protocol', 'enabled', 'profile'], expect: {} });
var profileIds = ['alt1', 'stock', 'overlap', 'fake', 'fake_split', 'fake_disorder'], targetIds = ['gitlab', 'unitask', 'tavily', 'youtube', 'discord'];
var profileNames = { alt1: _('Основной'), stock: _('Базовый'), overlap: _('Разделение с перекрытием'), fake: _('Ложный пакет'), fake_split: _('Ложный badsum + разделение'), fake_disorder: _('Ложный + перестановка') };
var profileNotes = {
	alt1: _('Кастомный Lua: один ложный hostname, остаток перед настоящим hostname. Проверялся ранее — не гарантия результата в вашей сети.'),
	stock: _('Штатный Lua: два ложных hostname вокруг настоящего, остаток в конце. Экспериментальный профиль.'),
	overlap: _('Разделение TLS с перекрытием частей. Экспериментальный профиль.'),
	fake: _('Ложный TLS-пакет перед исходным. Экспериментальный профиль.'),
	fake_split: _('С 0.4.4: ложный TLS с badsum ×10 и разделение 1,midsld. Проверялся на ресурсе Tavily, не на всём приложении. Прежние результаты fake_split относятся к старому варианту.'),
	fake_disorder: _('Ложный TLS-пакет и перестановка частей. Экспериментальный профиль.')
};
// Expected attempts come only from the acknowledged job, never the editable choices.
function profileCell(rows, expected, running) {
	var attempts = {};
	rows.forEach(function(row) {
		if (expected && row.repeat > expected) return;
		var key = row.repeat;
		attempts[key] = key in attempts ? attempts[key] && row.full_match : row.full_match;
	});
	var done = Object.keys(attempts).length;
	var success = Object.keys(attempts).filter(function(key) { return attempts[key]; }).length;
	var kind = !done ? (expected ? (running ? 'pending' : 'missing') : 'untested') :
		success && success < done ? 'mixed' : !success ? 'failure' :
		expected && done === expected ? 'success' : 'partial';
	var labels = { pending: _('… Ожидает'), missing: _('— Нет результата'), untested: _('— Не проверен'), mixed: _('± Смешанный'), failure: _('✕ Ошибка'), success: _('✓ Полностью'), partial: _('◐ Неполная проверка') };
	return { kind: kind, done: done,
		label: labels[kind] + (done ? ' · ' + success + '/' + (expected || done) : '') +
			(expected && done < expected && done ? (running ? ' · ' + _('ещё выполняется') : ' · ' + _('нет части попыток')) : '') };
}

var protocolIds = ['tcp', 'quic', 'udp'];
var protocolAllow = {
	tcp: { profiles: profileIds, targets: targetIds },
	quic: { profiles: ['quic_google', 'quic_zero', 'quic_google_badsum', 'quic_google_ttl2', 'quic_zero_badsum', 'quic_zero_ttl2'], targets: ['youtube_h3'] },
	udp: { profiles: ['udp_fake2', 'udp_fake6', 'udp_protocol_fake2', 'udp_badsum2', 'udp_ttl2', 'udp_protocol_badsum2'], targets: ['stun_google'] }
};
function checkedProfilesCatalog(reply) {
	requireOK(reply);
	var groups = reply.catalog && reply.catalog.groups;
	if (!Array.isArray(groups) || groups.length !== 3 || !groups.every(function(group, index) {
		var allow = protocolAllow[protocolIds[index]];
		return group && group.id === protocolIds[index] && typeof group.title === 'string' && typeof group.description === 'string' &&
			typeof group.test_supported === 'boolean' && typeof group.test_unavailable_reason === 'string' &&
			(group.test_supported || group.test_unavailable_reason.trim()) &&
			['profiles', 'targets'].every(function(key) {
				return Array.isArray(group[key]) && group[key].length > 0 && group[key].length <= allow[key].length &&
					group[key].every(function(item, i, items) {
						return item && allow[key].indexOf(item.id) !== -1 && typeof item.title === 'string' &&
							items.every(function(other, j) { return i === j || other.id !== item.id; }) &&
							(key === 'profiles' ? ['previously_verified', 'experimental'].indexOf(item.evidence) !== -1 && typeof item.strategy === 'string' : typeof item.description === 'string');
					});
			});
	})) throw new Error(_('Каталог протоколов недоступен или некорректен. Обновите пакет zapret2-home и ACL LuCI, затем перезагрузите страницу.'));
	return reply.catalog;
}
function checkedProfilesStatus(reply) {
	requireOK(reply);
	var data = reply.data, allow = data && protocolIds.indexOf(data.protocol) !== -1 && protocolAllow[data.protocol];
	if (!data || ['idle', 'pending', 'running', 'results', 'error'].indexOf(data.state) === -1 || typeof data.running !== 'boolean' ||
		(!allow && (data.protocol != null && data.protocol !== '' || data.state !== 'idle' || data.running || data.results && data.results.length)) ||
		!Array.isArray(data.results) || data.results.length > 60 ||
		!data.results.every(function(row) {
			return row && row.protocol === data.protocol && allow.profiles.indexOf(row.profile) !== -1 && allow.targets.indexOf(row.target) !== -1 &&
				(row.repeat === 1 || row.repeat === 2) && typeof row.full_match === 'boolean' && typeof row.failure === 'string' &&
				['status', 'bytes', 'time_total'].every(function(key) { return (data.protocol === 'udp' && row[key] == null) || typeof row[key] === 'number' && isFinite(row[key]) && row[key] >= 0; });
		}) || data.plan && (!allow || data.plan.protocol !== data.protocol || [1, 2].indexOf(data.plan.repeat) === -1 ||
			!['profiles', 'targets'].every(function(key) { return Array.isArray(data.plan[key]) && data.plan[key].length && data.plan[key].length <= allow[key].length && data.plan[key].every(function(id, i, ids) { return allow[key].indexOf(id) !== -1 && ids.indexOf(id) === i; }); })))
		throw new Error(_('Некорректный ответ protocols_status. Обновите пакет и ACL LuCI; управление заблокировано до достоверного статуса.'));
	return data;
}
function savedProtocol(status, id) {
	var branch = status && status.protocols && status.protocols[id];
	return branch && typeof branch.enabled === 'boolean' && protocolAllow[id].profiles.indexOf(branch.profile) !== -1 ? branch : null;
}

var fallbackCatalog = [
	{ id: 'flowseal', title: 'Flowseal', description: _('Сообщество: IP-список Flowseal') },
	{ id: 'cloudflare', title: 'Cloudflare', description: _('Сети Cloudflare') },
	{ id: 'hetzner', title: 'Hetzner', description: _('Сети Hetzner') },
	{ id: 'cloudfront', title: 'CloudFront', description: _('Сети CDN CloudFront') },
	{ id: 'ovh', title: 'OVH', description: _('Сети OVH') },
	{ id: 'digitalocean', title: 'DigitalOcean', description: _('Сети DigitalOcean') }
];

function checkedStatus(data) {
	if (!data || typeof data.running !== 'boolean' || typeof data.autostart !== 'boolean' ||
		['configure_pending', 'configure_recovery_required', 'update_running'].some(function(key) { return key in data && typeof data[key] !== 'boolean'; }))
		throw new Error(_('Некорректный ответ status от zapret2_home.'));
	return data;
}

function ipv4List(value, max, label) {
	var entries = value.trim().split(/[\s,]+/).filter(function(entry) { return entry !== ''; });
	if (!entries.length || entries.length > max)
		throw new Error(label + ': ' + _('требуется от 1 до') + ' ' + max + ' ' + _('IPv4-адресов или CIDR.'));
	entries.forEach(function(entry) {
		var parts = entry.split('/');
		var octets = parts[0].split('.');
		var valid = parts.length <= 2 && octets.length === 4 && octets.every(function(octet) {
			return /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255;
		});
		if (parts.length === 2)
			valid = valid && /^(0|[1-9][0-9]?)$/.test(parts[1]) && Number(parts[1]) <= 32;
		if (!valid)
			throw new Error(label + ': ' + _('недопустимый IPv4/CIDR') + ' — ' + entry);
	});
	return entries.join(' ');
}

function requireOK(result) {
	if (!result || result.ok !== true) {
		var detail = result && result.error ? String(result.error) : _('Операция не выполнена: некорректный или отрицательный ответ RPC.');
		if (result && typeof result.rolled_back === 'boolean')
			detail += ' ' + (result.rolled_back ? _('Предыдущие настройки восстановлены.') : _('Откат не выполнен — проверьте состояние службы.'));
		throw new Error(detail);
	}
	return result;
}

function updatedText(value) {
	if (!value) return '—';
	if (typeof value === 'number' || /^[0-9]+$/.test(String(value))) {
		var date = new Date(Number(value) * 1000);
		if (!isNaN(date.getTime())) return date.toLocaleString();
	}
	return String(value);
}

return view.extend({
	load: function() {
		return Promise.all([
			callStatus().then(checkedStatus).then(function(status) { return { status: status }; }).catch(function(error) { return { error: error }; }),
			callProfilesCatalog().then(checkedProfilesCatalog).catch(function(error) { return { error: error }; }),
			callProfilesStatus().then(checkedProfilesStatus).then(function(status) { return { data: status }; }).catch(function(error) { return { error: error }; })
		]).then(function(results) {
			results[0].profilesCatalog = results[1];
			results[0].profilesStatus = results[2];
			return results[0];
		});
	},

	render: function(data) {
		data = data || {};
		var initial = data.status;
		var busy = false, epoch = 0, pollPending = false, lastError = '', current = null;
		var controls = [], fields = {}, listInputs = {}, listLabels = {}, listStates = {};
		var listsUpdated = E('div', { id: 'zapret2-lists-updated', style: 'color:#666;margin-top:.5rem' });
		var saveButton, startButton, stopButton, restartButton, updateButton;
		var message = E('p', { id: 'zapret2-message', role: 'status', 'aria-live': 'polite' });
		var outputStyle = 'white-space:pre-wrap;overflow-wrap:anywhere;max-height:32rem;overflow:auto';
		var checkOutput = E('pre', { id: 'zapret2-check', style: outputStyle });
		var logOutput = E('pre', { id: 'zapret2-log', style: outputStyle });
		fields.running = E('strong', { id: 'zapret2-state', role: 'status', 'aria-live': 'polite' });
		function inputRow(title, id, node, description) {
			return E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title', 'for': id }, title),
				E('div', { 'class': 'cbi-value-field' }, [node,
					description ? E('div', { 'class': 'cbi-value-description' }, description) : ''
				])
			]);
		}
		function statusValue(key) {
			fields[key] = E('span', { id: 'zapret2-status-' + key, style: 'white-space:pre-wrap;overflow-wrap:anywhere' });
			return fields[key];
		}
		function diagnosticRow(title, value) {
			return E('div', { style: 'display:grid;grid-template-columns:minmax(0,9rem) minmax(0,1fr);gap:.25rem 1rem;padding:.25rem 0;text-align:left;overflow-wrap:anywhere' }, [
				E('span', {}, title), value
			]);
		}
		function statusRow(key, title) {
			return diagnosticRow(title, statusValue(key));
		}
		function advanced(title, children) {
			return E('details', { style: 'margin:.75rem 0;min-width:0' }, [E('summary', { style: 'cursor:pointer' }, title), E('div', { style: 'margin-top:.5rem' }, children)]);
		}
		function setMessage(value, error) {
			message.textContent = value;
			message.style.color = error ? '#b00' : '';
			message.style.display = value ? '' : 'none';
		}
		function fail(error) {
			var detail = error && error.message ? error.message : String(error);
			setMessage(_('Ошибка:') + ' ' + detail, true);
			if (detail !== lastError) {
				var notice = E('p');
				notice.textContent = detail;
				ui.addNotification(null, notice, 'error');
			}
			lastError = detail;
		}
		function syncControls() {
			var applying = current && (current.configure_pending === true || current.configure_recovery_required === true);
			controls.forEach(function(control) { control.disabled = busy || applying; });
			function serviceAction(control, visible) {
				if (!control) return;
				control.hidden = !visible;
				control.style.display = visible ? '' : 'none';
				control.disabled = busy || !visible;
			}
			serviceAction(startButton, !!current && !applying && !current.running);
			serviceAction(stopButton, !!current && !applying && current.running);
			serviceAction(restartButton, !!current && !applying && current.running);
			if (saveButton) saveButton.disabled = busy || applying || !current || current.update_running === true;
			if (updateButton) updateButton.disabled = busy || applying || !current || current.update_running === true;
			syncProfileControls();
		}
		function applyStatus(status) {
			var updateWasRunning = current && current.update_running === true;
			current = status;
			fields.running.textContent = status.configure_pending ? _('Применяются настройки') : status.running ? _('Запущен') : _('Остановлен');
			fields.process.textContent = fields.running.textContent;
			fields.package.textContent = status.package_version || '—';
			fields.engine.textContent = status.engine_version || '—';
			fields.profile.textContent = status.profile || '—';
			fields.clients.textContent = status.client_mode === 'all' ? _('Все устройства LAN (кроме роутера)') : status.clients || '—';
			fields.destinations.textContent = status.destinations || _('Нет ручных IP/подсетей');
			fields.lists.textContent = status.lists || _('Не выбраны');
			fields.table.textContent = status.table_present === true ? _('Присутствует') : status.table_present === false ? _('Отсутствует') : _('Неизвестно');
			fields.queue.textContent = status.queue == null ? '—' : String(status.queue);
			fields.integrity.textContent = status.integrity_ok === true ? _('Проверена') : status.integrity_ok === false ? _('Нарушена — проверьте пакет') : _('Неизвестно');
			// These two fixed backend notices are covered by the single scope note below.
			var routineWarnings = ['Только выбранные прямые IPv4 TCP/443. VPN-маршруты не изменяются.', 'HTTP/3, IPv6 и работа приложений целиком этой версией не проверяются.'];
			fields.warnings.textContent = Array.isArray(status.warnings) ? status.warnings.map(String).filter(function(warning) { return routineWarnings.indexOf(warning) === -1; }).join('\n') : _('Неизвестно');
			fields.warnings.parentNode.style.display = fields.warnings.textContent ? '' : 'none';
			fields.counters.textContent = status.rule_counters || _('Нет данных');
			fields.update.textContent = status.update_running === true ? _('Обновление выполняется') : _('Обновление не выполняется');
			fields.update_error.textContent = status.update_error || '';
			fields.update_error.parentNode.style.display = fields.update_error.textContent ? '' : 'none';
			var catalog = Array.isArray(status.list_catalog) ? status.list_catalog : [];
			var states = status.list_state && typeof status.list_state === 'object' ? status.list_state : {};
			var details = [], updates = [];
			fallbackCatalog.forEach(function(fallback) {
				var item = catalog.filter(function(entry) { return entry && entry.id === fallback.id; })[0] || fallback;
				var state = states[fallback.id];
				var loaded = state && Number.isSafeInteger(Number(state.count)) && Number(state.count) > 0;
				listStates[fallback.id].textContent = loaded ? String(Number(state.count)).replace(/\B(?=(\d{3})+(?!\d))/g, ' ') + ' ' + _('сетей') : _('не загружен');
				listLabels[fallback.id].title = (typeof item.description === 'string' ? item.description : fallback.description) + (loaded && state.updated ? '\n' + _('Обновлён:') + ' ' + updatedText(state.updated) : '') + (state && state.error ? '\n' + String(state.error) : '');
				if (loaded && state.updated) updates.push(state.updated);
				if (state) details.push(fallback.title + ': ' + _('SHA256') + ' ' + (state.sha256 || '—') + (state.error ? '\n' + String(state.error) : ''));
			});
			var sameUpdate = updates.every(function(value) { return String(value) === String(updates[0]); });
			var latestUpdate = updates.slice().sort(function(a, b) {
				function time(value) { return /^[0-9]+$/.test(String(value)) ? Number(value) * 1000 : Date.parse(String(value)) || 0; }
				return time(b) - time(a);
			})[0];
			listsUpdated.textContent = updates.length ? (sameUpdate ? _('Обновлены:') : _('Последнее обновление:')) + ' ' + updatedText(latestUpdate) : '';
			listsUpdated.style.display = updates.length ? '' : 'none';
			fields.list_details.textContent = details.join('\n') || _('Нет данных');
			syncControls();
			if (updateWasRunning && !status.update_running && status.update_error)
				fail(new Error(status.update_error));
			if (status.configure_recovery_required)
				fail(new Error(status.configure_result && status.configure_result.error || _('Сохранение прервано; требуется проверка восстановления.')));
		}
		function awaitConfigure(reply) {
			requireOK(reply);
			if (reply.pending !== true) return Promise.resolve(reply);
			if (!/^[0-9]+$/.test(String(reply.job_id || '')))
				return Promise.reject(new Error(_('Не получен идентификатор задания сохранения.')));
			var deadline = Date.now() + 90000;
			function inspect() {
				return refresh().then(function() {
					if (!current || String(current.configure_job_id) !== String(reply.job_id))
						throw new Error(_('Статус задания сохранения изменился; проверьте настройки.'));
					if (current.configure_result) {
						if (String(current.configure_result.job_id) !== String(reply.job_id))
							throw new Error(_('Результат относится к другому заданию сохранения.'));
						if (current.configure_pending === false) {
							var result = requireOK(current.configure_result);
							if (current.configure_recovery_required === true) throw new Error(_('Восстановление настроек не подтверждено.'));
							return result;
						}
					}
					if (!current.configure_pending || Date.now() >= deadline)
						throw new Error(_('Завершение сохранения не подтверждено; проверьте состояние.'));
					return new Promise(function(resolve) { setTimeout(resolve, 1000); }).then(inspect);
				});
			}
			return inspect();
		}
		function refresh() {
			var generation = epoch;
			return callStatus().then(checkedStatus).then(function(status) {
				if (generation === epoch) applyStatus(status);
			}).catch(function(error) {
				if (generation === epoch) {
					current = null;
					fields.running.textContent = _('Состояние неизвестно: status недоступен');
					fields.process.textContent = _('Неизвестно: status недоступен');
					syncControls();
					throw error;
				}
			});
		}
		function run(label, work) {
			if (busy) return Promise.resolve();
			busy = true;
			epoch++;
			syncControls();
			setMessage(_('Выполняется:') + ' ' + label, false);
			return Promise.resolve().then(work).then(function() {
				lastError = '';
				setMessage('', false);
			}).catch(fail).finally(function() {
				busy = false;
				syncControls();
			});
		}
		// A rejected write may still have changed state (including backend rollback).
		// Always read back before releasing controls; never send a frontend restart.
		function write(request, validate) {
			var failure, result;
			return request.then(function(reply) {
				result = (validate || requireOK)(reply);
			}).catch(function(error) { failure = error; }).then(function() {
				return refresh().catch(function(error) {
					if (failure) throw new Error((failure.message || String(failure)) + '\n' + (error.message || String(error)));
					throw error;
				});
			}).then(function() {
				if (failure) throw failure;
				return result;
			});
		}
		function button(id, label, work) {
			var node = E('button', {
				id: id, 'class': 'cbi-button cbi-button-action', type: 'button',
				click: function() { if (!node.disabled) return run(label, work); return Promise.resolve(); }
			}, label);
			controls.push(node);
			return node;
		}
		var wide = 'width:100%;max-width:54rem;box-sizing:border-box';
		var clients = E('textarea', { id: 'zapret2-clients', rows: '3', 'class': 'cbi-input-textarea', style: wide });
		var destinations = E('textarea', { id: 'zapret2-destinations', rows: '4', 'class': 'cbi-input-textarea', style: wide });
		var autostart = E('input', { id: 'zapret2-autostart', type: 'checkbox' });
		var autoUpdate = E('input', { id: 'zapret2-auto-update', type: 'checkbox' });
		var clientsRow;
		function syncClientMode() {
			clientsRow.hidden = clientMode.value === 'all';
			// Native themes set .cbi-value display explicitly, overriding HTML hidden.
			clientsRow.style.display = clientsRow.hidden ? 'none' : '';
		}
		var clientMode = E('select', { id: 'zapret2-client-mode', 'class': 'cbi-input-select', change: syncClientMode }, [
			E('option', { value: 'selected' }, _('Выбранные устройства')),
			E('option', { value: 'all' }, _('Все устройства LAN'))
		]);
		clients.value = initial && typeof initial.clients === 'string' ? initial.clients : '';
		destinations.value = initial && typeof initial.destinations === 'string' ? initial.destinations : '';
		clientMode.value = initial && initial.client_mode === 'all' ? 'all' : 'selected';
		autostart.checked = !!(initial && initial.autostart);
		autoUpdate.checked = !!(initial && initial.auto_update === true);
		controls.push(clients, destinations, clientMode, autostart, autoUpdate);
		clientsRow = inputRow(_('IPv4 / подсети клиентов'), 'zapret2-clients', clients, _('1–16 частных IPv4 / CIDR (/24–/32), через пробел или новую строку.'));
		syncClientMode();
		var selectedLists = initial && typeof initial.lists === 'string' ? initial.lists.trim().split(/\s+/) : [];
		var listChoices = E('div', { id: 'zapret2-list-choices', style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,14rem),1fr));gap:.5rem 1rem;width:100%;max-width:54rem' }, fallbackCatalog.map(function(item) {
			var input = E('input', { id: 'zapret2-list-' + item.id, type: 'checkbox', value: item.id });
			input.checked = selectedLists.indexOf(item.id) !== -1;
			listInputs[item.id] = input;
			controls.push(input);
			listLabels[item.id] = E('span', { id: 'zapret2-list-label-' + item.id });
			listStates[item.id] = E('span', { id: 'zapret2-list-state-' + item.id, style: 'color:#666;font-size:.9em;white-space:nowrap' });
			listLabels[item.id].textContent = item.title;
			return E('div', { style: 'display:flex;flex-wrap:wrap;align-items:baseline;gap:.15rem .5rem;min-width:0' }, [E('label', { 'for': 'zapret2-list-' + item.id }, [input, ' ', listLabels[item.id]]), listStates[item.id]]);
		}));
		saveButton = button('zapret2-save', _('Сохранить и применить'), function() {
			if (!current || current.update_running === true) throw new Error(_('Дождитесь завершения операции и обновления статуса.'));
			if (clientMode.value !== 'selected' && clientMode.value !== 'all') throw new Error(_('Недопустимый режим клиентов.'));
			var clientList = clientMode.value === 'all' ? '' : ipv4List(clients.value, 16, _('Клиенты'));
			var lists = fallbackCatalog.filter(function(item) { return listInputs[item.id].checked; }).map(function(item) { return item.id; }).join(' ');
			var destinationList = destinations.value.trim() ? ipv4List(destinations.value, 64, _('Ручные IP/подсети')) : '';
			if (!lists && !destinationList) throw new Error(_('Выберите хотя бы один список сообщества или укажите ручные IP/подсети.'));
			return write(callConfigure(clientList, destinationList, autostart.checked, clientMode.value, lists, autoUpdate.checked).then(awaitConfigure));
		});
		startButton = button('zapret2-start', _('Запустить'), function() { return write(callControl('start')); });
		stopButton = button('zapret2-stop', _('Остановить всё'), function() { return write(callControl('stop')); });
		restartButton = button('zapret2-restart', _('Перезапустить'), function() { return write(callControl('restart')); });
		updateButton = button('zapret2-update-lists', _('Обновить списки'), function() {
			return write(callUpdateLists(), function(result) {
				requireOK(result);
				if (result.pending !== true) throw new Error(_('Некорректный ответ update_lists от zapret2_home.'));
				return result;
			}).then(function() {
				if (current && !current.update_running && current.update_error) throw new Error(current.update_error);
			});
		});
		var settings = E('div', { 'class': 'cbi-tab-container', 'data-tab': 'settings', 'data-tab-title': _('Настройки'), 'data-tab-active': 'true' }, [
			inputRow(_('Клиенты'), 'zapret2-client-mode', clientMode, _('«Все» — устройства LAN, кроме роутера.')),
			clientsRow,
			inputRow(_('Списки сообщества'), null, E('div', {}, [listChoices, listsUpdated, E('div', { style: 'margin-top:.5rem;color:#666' }, _('Подсети серверов'))])),
			inputRow(_('Обновление списков'), 'zapret2-auto-update', E('div', {}, [E('label', { 'for': 'zapret2-auto-update' }, [autoUpdate, ' ', _('Автоматически, раз в сутки')]), ' ', updateButton]), _('Автообновление работает только пока основная служба запущена. Кнопка обновляет сохранённый выбор; сначала сохраните изменения.')),
			inputRow(_('Ручные IP / подсети'), 'zapret2-destinations', destinations, _('Не домены. До 64 публичных IPv4 / CIDR (/16–/32); необязательно при выбранном списке сообщества.')),
			inputRow(_('Автозапуск'), 'zapret2-autostart', E('label', { 'for': 'zapret2-autostart' }, [autostart, ' ', _('Запускать при загрузке роутера')])),
			E('div', { 'class': 'cbi-section-descr' }, _('Запущенная служба перезапустится для применения изменений; остановленная не запускается.')),
			E('div', { 'class': 'cbi-page-actions' }, [saveButton])
		]);
		var diagnostics = E('div', { 'class': 'cbi-tab-container', 'data-tab': 'diagnostics', 'data-tab-title': _('Диагностика') }, [
			E('p', { 'class': 'cbi-section-descr' }, _('Статус процесса не подтверждает обход блокировок. Проверки TCP, QUIC и STUN доступны во вкладке «Профили»; IPv6 и работа приложений целиком не проверяются.')),
			E('div', { id: 'zapret2-diagnostic-summary' }, [
				diagnosticRow(_('Версии'), E('span', {}, [_('Пакет') + ' ', statusValue('package'), ' · ' + _('движок') + ' ', statusValue('engine')])),
				statusRow('process', _('Процесс')), statusRow('profile', _('Профиль')),
				diagnosticRow(_('Правила firewall'), E('span', {}, ['nftables: ', statusValue('table'), ' · NFQUEUE ', statusValue('queue')])),
				statusRow('integrity', _('Целостность')), statusRow('update', _('Обновление списков')),
				statusRow('warnings', _('Предупреждения')), statusRow('update_error', _('Ошибка обновления'))
			]),
			advanced(_('Сохранённая область'), [statusRow('clients', _('Клиенты')), statusRow('destinations', _('Ручные IP/подсети')), statusRow('lists', _('Списки'))]),
			advanced(_('Счётчики правил'), [statusRow('counters', _('Счётчики'))]),
			advanced(_('Контрольные суммы / ошибки списков'), [statusRow('list_details', _('SHA-256'))]),
			button('zapret2-check-button', _('Проверить'), function() {
				checkOutput.textContent = '';
				return callCheck().then(function(result) {
					if (!result || typeof result.details !== 'string' || typeof result.ok !== 'boolean') throw new Error(_('Некорректный ответ check от zapret2_home.'));
					checkOutput.textContent = result.details;
					if (!result.ok) throw new Error(result.details || _('Проверка завершилась ошибкой.'));
				});
			}), checkOutput
		]);
		var journal = E('div', { 'class': 'cbi-tab-container', 'data-tab': 'journal', 'data-tab-title': _('Журнал') }, [
			button('zapret2-log-button', _('Показать журнал'), function() {
				logOutput.textContent = '';
				return callLogs().then(function(result) {
					if (!result || typeof result.log !== 'string') throw new Error(_('Некорректный ответ logs от zapret2_home.'));
					logOutput.textContent = result.log || _('Журнал пуст.');
				});
			}), logOutput
		]);
		var profilesState = data.profilesStatus && data.profilesStatus.data;
		var profilesKnown = !!profilesState;
		var profilesAvailable = !!data.profilesCatalog && !data.profilesCatalog.error;
		var profilesLaunching = false, profilesPolling = false, profilesEpoch = 0, profilesJob = '', jobPlan = null;
		var profilesError = data.profilesCatalog && data.profilesCatalog.error || data.profilesStatus && data.profilesStatus.error;
		var protocolViews = [], protocolSummaries = {}, launchProtocol = 'tcp';
		var summaryState = E('p', { id: 'zapret2-protocol-saved-state', role: 'status', 'aria-live': 'polite' });
		function syncProfileControls() {
			var context = !current ? _('Статус неизвестен; сохранённые данные не подтверждены.') : current.configure_recovery_required ? _('Восстановление не подтверждено: состояние может быть неактуально.') : current.configure_pending ? _('Применение ещё выполняется; показаны последние сохранённые данные.') : !current.running ? _('Служба остановлена: сохранённые профили сейчас не работают.') : _('Служба запущена; работа профилей и приложений не подтверждена.');
			if (summaryState.textContent !== context) summaryState.textContent = context;
			protocolIds.forEach(function(id) {
				var node = protocolSummaries[id], saved = savedProtocol(current, id);
				if (!node) return;
				var value = !saved ? _('Неизвестно: сохранённое состояние не подтверждено') :
					(saved.enabled ? _('Включён в настройках') + ' · ' + saved.profile : _('Выключен в настройках'));
				if (node.textContent !== value) node.textContent = value;
			});
			protocolViews.forEach(function(item) { item.sync(); });
		}
		function showProfiles() { protocolViews.forEach(function(item) { item.show(); }); syncProfileControls(); }
		function refreshProfiles() {
			var generation = profilesEpoch;
			return callProfilesStatus().then(checkedProfilesStatus).then(function(state) {
				if (generation !== profilesEpoch) return;
				if (profilesJob && (state.job_id !== profilesJob || jobPlan && state.protocol !== jobPlan.protocol))
					throw new Error(_('Завершение задания не подтверждено: другой job_id или протокол.'));
				profilesState = state; profilesKnown = true; profilesError = null;
				showProfiles();
			}).catch(function(error) {
				if (generation !== profilesEpoch) return;
				profilesError = error; profilesKnown = false; showProfiles(); throw error;
			});
		}
		var profileNamesTCP = profileNames, profileNotesTCP = profileNotes;
		function buildProtocol(group) {
		var protocol = group.id, profileIds = group.profiles.map(function(item) { return item.id; }), targetIds = group.targets.map(function(item) { return item.id; });
		var profileNames = {}, profileNotes = {}, targetNames = {};
		group.profiles.forEach(function(item) {
			profileNames[item.id] = protocol === 'tcp' ? (profileNamesTCP[item.id] || item.title) : item.title + ' · ' + _('экспериментальный');
			profileNotes[item.id] = protocol === 'tcp' ? profileNotesTCP[item.id] :
				(item.id.indexOf('badsum') !== -1 ? _('Вариант с неверной контрольной суммой (badsum). ') : item.id.indexOf('ttl2') !== -1 ? _('Вариант с TTL 2. ') : '') +
				_('Экспериментальный профиль; варианты параметров не являются отдельными алгоритмами. Результат в вашей сети не гарантирован.');
		});
		group.targets.forEach(function(item) { targetNames[item.id] = item.id === 'youtube' ? _('YouTube — изображение TCP') : item.id === 'discord' ? _('Discord — CSS TCP') : item.id === 'youtube_h3' ? _('YouTube — изображение HTTP/3, не видео') : item.id === 'stun_google' ? _('STUN — не голосовая связь') : item.title; });
		function profileLabel(id) { return profileNames[id] + ' · ' + id; }
		function protocolElement(tag, attrs, children) {
			if (attrs && protocol !== 'tcp') ['id', 'for', 'aria-labelledby', 'aria-describedby'].forEach(function(key) {
				if (attrs[key]) attrs[key] = attrs[key].replace(/zapret2-/g, 'zapret2-' + protocol + '-');
			});
			return E(tag, attrs, children);
		}
		var staged = false, lastState = null, lastPlan = null;
		function stage() { staged = true; syncProfileControls(); }
		var activeProfile = protocolElement('strong', { id: 'zapret2-active-profile', role: 'status', 'aria-live': 'polite' });
		activeProfile.textContent = _('Неизвестен: status недоступен');
		var savedProfileHint = protocolElement('span', { id: 'zapret2-saved-profile-hint', 'class': 'z2-muted' });
		var profilesMessage = protocolElement('p', { id: 'zapret2-profiles-state', role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true', style: 'overflow-wrap:anywhere' });
		var progressBar = protocolElement('progress', { id: 'zapret2-profiles-progress', 'aria-label': _('Выполненные проверки, не завершение задания'), 'aria-describedby': 'zapret2-profiles-state', style: 'display:block;width:100%;height:1.25rem' });
		var progressNote = protocolElement('p', { 'class': 'z2-muted' });
		var progressPanel = protocolElement('div', { id: 'zapret2-profiles-progress-panel', 'class': 'z2-progress', 'aria-label': _('Прогресс теста') }, [profilesMessage, progressBar, progressNote]);
		var profilesResults = protocolElement('div', { id: 'zapret2-profiles-results', 'aria-label': _('Результаты сравнения профилей') });
		var selectionHint = protocolElement('p', { id: 'zapret2-test-plan', 'class': 'z2-muted' });
		var testHint = protocolElement('p', { id: 'zapret2-test-hint', 'class': 'z2-muted' });
		var applyHint = protocolElement('p', { id: 'zapret2-apply-hint', 'class': 'z2-muted' });
		var technicalOutput = protocolElement('pre', { id: 'zapret2-profiles-technical', style: outputStyle });
		var renderedResults = '', renderedProgress = '';
		var profileInputs = {}, targetInputs = {}, profilesControls = [];
		function selection(ids, inputs) {
			return ids.filter(function(id) { return inputs[id].checked; });
		}
		function profileChoices(ids, inputs, kind) {
			var choices = protocolElement('div', { 'class': 'z2-choices z2-choices-' + kind }, ids.map(function(id) {
				var input = protocolElement('input', { id: 'zapret2-test-' + kind + '-' + id, type: 'checkbox', value: id, change: syncProfileControls });
				input.checked = protocol === 'tcp' ? (kind === 'profile' ? id === 'alt1' || id === 'stock' : ['gitlab', 'unitask', 'tavily'].indexOf(id) !== -1) : true;
				inputs[id] = input;
				profilesControls.push(input);
				return protocolElement('label', { 'for': 'zapret2-test-' + kind + '-' + id, title: kind === 'profile' ? profileNotes[id] : targetNames[id] }, [input, ' ',
					kind === 'profile' ? protocolElement('span', {}, [profileNames[id], ' ', protocolElement('small', { 'class': 'z2-muted' }, id)]) : targetNames[id]]);
			}));
			return protocolElement('div', {}, [protocolElement('div', { style: 'display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem' }, [true, false].map(function(checked) {
				var control = protocolElement('button', { id: 'zapret2-test-' + kind + (checked ? '-all' : '-clear'), type: 'button', 'class': 'cbi-button', click: function() {
					if (control.disabled) return;
					ids.forEach(function(id) { inputs[id].checked = checked; });
					syncProfileControls();
				} }, checked ? _('Выбрать все') : _('Очистить выбор'));
				profilesControls.push(control);
				return control;
			})), choices]);
		}
		function profilesBlocked() {
			return !profilesAvailable || !profilesKnown || !profilesState || profilesState.running || profilesState.state === 'pending' || profilesState.state === 'running';
		}
		function mainBlocked() {
			return !current || current.configure_pending !== false || current.configure_recovery_required !== false || current.update_running !== false;
		}
		function syncBranchControls() {
			var saved = savedProtocol(current, protocol);
			if (saved && !staged && applyCandidate.value !== (saved.enabled ? saved.profile : '')) applyCandidate.value = saved.enabled ? saved.profile : '';
			var savedLabel = saved ? (saved.enabled ? (profileNames[saved.profile] ? profileLabel(saved.profile) : saved.profile) : _('Выключено')) : _('Неизвестен: сохранённый профиль не подтверждён');
			if (activeProfile.textContent !== savedLabel) activeProfile.textContent = savedLabel;
			var allOff = saved && !applyCandidate.value && protocolIds.every(function(id) { var branch = savedProtocol(current, id); return branch && (id === protocol || !branch.enabled); });
			var blocked = busy || mainBlocked() || profilesLaunching || profilesBlocked() || !saved || !protocolIds.every(function(id) { return savedProtocol(current, id); });
			profilesControls.forEach(function(control) { control.disabled = !!blocked; });

			var profiles = selection(profileIds, profileInputs), targets = selection(targetIds, targetInputs);
			if (profilesStart) profilesStart.disabled = !!blocked || !group.test_supported || !profiles.length || !targets.length;
			if (applyCandidate) applyCandidate.disabled = !!blocked;
			var unchanged = saved && (saved.enabled ? applyCandidate.value === saved.profile : applyCandidate.value === '');
			if (applyButton) applyButton.disabled = !!blocked || !!allOff || applyCandidate.value !== '' && profileIds.indexOf(applyCandidate.value) === -1 || !!unchanged;
			selectionHint.textContent = profiles.length + ' ' + _('профиля') + ' × ' + targets.length + ' ' + _('сервиса') + ' × ' + (profilesRepeat ? profilesRepeat.value : '1') + ' = ' +
				(profiles.length * targets.length * (profilesRepeat ? Number(profilesRepeat.value) : 1)) + ' ' + _('проверок. Может занять несколько минут.');
			var reason = busy ? _('Дождитесь текущей операции.') : !current ? _('Статус основной службы неизвестен.') :
				current.configure_pending == null || current.configure_recovery_required == null || current.update_running == null ? _('Статус применения, восстановления или обновления списков неизвестен. Обновите состояние страницы.') :
				current.configure_recovery_required ? _('Сначала проверьте восстановление настроек.') : current.configure_pending ? _('Настройки ещё применяются.') :
				current.update_running ? _('Дождитесь обновления списков.') : !protocolIds.every(function(id) { return savedProtocol(current, id); }) ? _('Сохранённое состояние протоколов неизвестно. Обновите пакет zapret2-home и ACL LuCI, затем перезагрузите страницу.') : !profilesAvailable ? _('Каталог недоступен. Обновите пакет zapret2-home и ACL LuCI, затем перезагрузите страницу.') :
				!profilesKnown ? _('Статус теста неизвестен: ожидается подтверждение.') : profilesLaunching ? _('Запуск теста…') :
				profilesBlocked() ? _('Дождитесь завершения теста и очистки.') : '';
			testHint.textContent = reason || (!group.test_supported ? group.test_unavailable_reason : '') || (!profiles.length || !targets.length ? _('Выберите хотя бы один профиль и сервис.') : _('Тест изолирован: сохранённый профиль и настройки не меняются.'));
			applyHint.textContent = reason || (!saved ? _('Сохранённое состояние не подтверждено.') : allOff ? _('Нельзя выключить последний протокол. Для остановки всей службы нажмите «Остановить всё».') :
				unchanged ? _('Этот выбор уже сохранён.') : _('Не сохранено. К применению:') + ' ' + (applyCandidate.value ? profileLabel(applyCandidate.value) : _('Выключено')) + '. ' + _('Результат теста не гарантирует работу приложений.'));
			savedProfileHint.textContent = !current ? _('Состояние службы неизвестно.') : current.configure_pending ? _('Изменение ещё не завершено.') :
				current.configure_recovery_required ? _('Восстановление не подтверждено; состояние неактуально.') : current.running ? (saved && !saved.enabled ? _('Протокол выключен в настройках; остальные протоколы не изменены.') : _('Служба запущена; работа этого профиля и доступность приложений не подтверждены.')) : _('Служба остановлена: это сохранённый профиль, не работающая стратегия.');
		}
		function showBranch() {
			if (profilesState && profilesState.protocol === protocol) {
				lastState = profilesState;
				lastPlan = jobPlan && jobPlan.protocol === protocol && profilesState.job_id === jobPlan.job_id ? jobPlan : profilesState.plan ? Object.assign({ job_id: profilesState.job_id }, profilesState.plan) : null;
			}
			var state = lastState || { state: 'idle', running: false, results: [] }, rows = state.results, plan = lastPlan;
			var completed = {};
			rows.forEach(function(row) {
				if (!plan || plan.profiles.indexOf(row.profile) !== -1 && plan.targets.indexOf(row.target) !== -1 && row.repeat <= plan.repeat)
					completed[row.profile + '/' + row.target + '/' + row.repeat] = true;
			});
			var done = Object.keys(completed).length, total = plan ? plan.profiles.length * plan.targets.length * plan.repeat : 0;
			var launching = profilesLaunching && launchProtocol === protocol && !profilesJob;
			var cleanup = state && state.running && (state.state === 'results' || total && done === total);
			var barDisplay = profilesKnown && state && state.state === 'idle' && !launching ? 'none' : 'block';
			if (progressBar.style.display !== barDisplay) progressBar.style.display = barDisplay;
			var labels = { idle: _('Тест не запущен'), pending: _('Задание принято; результат ещё не подтверждён'), running: _('Проверки выполняются'), results: cleanup ? _('Результаты получены') : _('Тест завершён'), error: _('Ошибка теста') };
			var progress = (launching ? _('Запуск теста…') : profilesKnown && state ? labels[state.state] : _('Статус теста неизвестен')) +
				(!launching && state && state.state !== 'idle' ? ' · ' + (profilesKnown ? _('Проверки:') : _('Последние данные:')) + ' ' + done +
					(total ? '/' + total + (profilesKnown ? ' · ' + Math.floor(done * 100 / total) + '%' : '') : ' · ' + _('план запуска неизвестен')) : '') +
				(!launching && profilesKnown && state && state.running ? ' · ' + (cleanup ? _('Очистка ещё выполняется; завершение не подтверждено.') : _('Тест/очистка ещё выполняются; завершение не подтверждено.')) : '') +
				(state && state.error ? '\n' + String(state.error) : '') + (profilesError ? '\n' + _('Ошибка:') + ' ' + (profilesError.message || String(profilesError)) : '');
			if (profilesMessage.textContent !== progress) profilesMessage.textContent = progress;
			profilesMessage.style.color = profilesError || state && state.error ? '#b00' : '';
			var barSignature = JSON.stringify([!!(profilesKnown && total && !launching), done, total]);
			if (barSignature !== renderedProgress) {
				renderedProgress = barSignature;
				if (profilesKnown && total && !launching) { progressBar.max = total; progressBar.value = done; }
				else progressBar.removeAttribute('value');
			}
			var note = !profilesKnown ? _('Статус недоступен: показаны последние известные результаты, не текущий прогресс.') :
				launching ? _('Ожидается подтверждение запуска.') : state && state.state === 'idle' ? _('Прогресс появится после подтверждения запуска.') : !total ? _('Без принятого плана процент выполнения неизвестен.') :
				cleanup ? _('Получение результатов не означает завершение задания. Дождитесь подтверждения очистки.') :
				state && (state.state === 'running' || state.state === 'pending') ? _('Счётчик меняется после завершения попытки; текущая загрузка может занять время.') :
				done < total ? _('Получены не все запланированные попытки.') : _('Все запланированные попытки получены.');
			if (progressNote.textContent !== note) progressNote.textContent = note;
			var signature = JSON.stringify([rows, plan, state && state.job_id, !!(state && state.running), profilesKnown]);
			if (signature !== renderedResults) {
				renderedResults = signature;
				profilesResults.textContent = '';

				if (rows.length || plan) {
					profilesResults.appendChild(protocolElement('table', { 'class': 'table cbi-section-table z2-matrix' }, [
						protocolElement('caption', {}, _('Сравнение профилей') + (plan ? '' : ' · ' + _('полнота плана неизвестна')) + ' · ' + (protocol === 'udp' ? _('В ячейках: строгих STUN-ответов / попыток') : _('В ячейках: полных загрузок / попыток'))),
						protocolElement('thead', {}, [protocolElement('tr', { 'class': 'tr' }, [protocolElement('th', { scope: 'col' }, _('Профиль'))].concat(targetIds.map(function(id) { return protocolElement('th', { scope: 'col' }, targetNames[id]); })))]),
						protocolElement('tbody', {}, profileIds.map(function(id) {
							var covered = 0, tested = 0, mixed = 0, incomplete = 0, expectedTargets = plan && plan.profiles.indexOf(id) !== -1 ? plan.targets.length : 0;
							var cells = targetIds.map(function(target) {
								var expected = expectedTargets && plan.targets.indexOf(target) !== -1 ? plan.repeat : 0;
								var cell = profileCell(rows.filter(function(row) { return (!plan || expected) && row.profile === id && row.target === target; }), expected, !!(state && state.running));
								if (cell.done) tested++;
								if (cell.kind === 'success') covered++;
								if (cell.kind === 'mixed') mixed++;
								if (expected && cell.done < expected) incomplete++;
								return protocolElement('td', { 'class': 'td z2-cell', 'data-label': targetNames[target], 'data-result': cell.kind, id: 'zapret2-result-' + id + '-' + target }, [protocolElement('span', { 'class': 'z2-service', 'aria-hidden': 'true' }, targetNames[target]), protocolElement('span', {}, cell.label)]);
							});
							return protocolElement('tr', { 'class': 'tr' }, [protocolElement('th', { scope: 'row', 'class': 'z2-profile' }, [protocolElement('strong', {}, profileNames[id]), ' ', protocolElement('small', { 'class': 'z2-muted' }, id),
								protocolElement('div', { id: 'zapret2-result-summary-' + id, 'class': 'z2-muted' }, expectedTargets ? _('Полностью:') + ' ' + covered + '/' + expectedTargets +
									(mixed ? ' · ' + _('Смешано:') + ' ' + mixed : '') + (incomplete ? ' · ' + _('Не завершено:') + ' ' + incomplete : '') :
									plan ? _('Не проверен') : _('Проверено сервисов:') + ' ' + tested + '/' + targetIds.length + ' · ' + _('план неизвестен'))])].concat(cells));
						}))
					]));
				} else profilesResults.textContent = group.test_supported ? _('Результатов пока нет. Начните тест кнопкой выше.') : _('Автоматический тест недоступен. Причина указана выше; профиль можно применить вручную.');
				technicalOutput.textContent = _('Задание:') + ' ' + (state && state.job_id || '—') + '\n' + (rows.length ? rows.map(function(row) {
					var metadata = group.profiles.filter(function(item) { return item.id === row.profile; })[0];
					return row.profile + ' / ' + row.target + ' #' + row.repeat + (protocol === 'udp' ? ' · STUN ' : ' · HTTP ') + (row.status == null ? '—' : row.status) + ' · ' + (row.bytes == null ? '—' : row.bytes) + ' B · ' + (row.time_total == null ? '—' : row.time_total) + ' s · ' +
						(row.full_match ? (protocol === 'udp' ? _('Строгий STUN-ответ, не голос') : _('Полная загрузка')) + ' (full_match)' : _('Ошибка') + ' (failure): ' + (row.failure || _('неполное совпадение'))) + '\n' + _('Стратегия:') + ' ' + (metadata && typeof metadata.strategy === 'string' ? metadata.strategy : _('нет данных')) + '\n' + JSON.stringify(row);
				}).join('\n') : _('Нет попыток.'));
			}
			syncProfileControls();
		}
		var profilesRepeat = protocolElement('select', { id: 'zapret2-test-repeat', 'class': 'cbi-input-select', change: syncProfileControls }, [protocolElement('option', { value: '1' }, '1'), protocolElement('option', { value: '2' }, '2')]);
		profilesRepeat.value = '1';
		profilesControls.push(profilesRepeat);
		var profilesStart = protocolElement('button', {
			id: 'zapret2-profiles-start', 'class': 'cbi-button cbi-button-action', type: 'button', 'aria-describedby': 'zapret2-test-plan zapret2-test-hint',
			click: function() {
				if (profilesStart.disabled) return Promise.resolve();
				var profiles = selection(profileIds, profileInputs), targets = selection(targetIds, targetInputs), repeat = Number(profilesRepeat.value);
				if (!profiles.length || !targets.length || (repeat !== 1 && repeat !== 2)) {
					profilesError = new Error(_('Выберите профили, цели и 1 или 2 повтора.'));
					showProfiles();
					return Promise.resolve();
				}
				profilesLaunching = true; launchProtocol = protocol;
				profilesEpoch++;
				profilesJob = '';
				showProfiles();
				var failure;
				return Promise.all([refresh(), refreshProfiles()]).then(function() {
					if (busy || mainBlocked() || !protocolIds.every(function(id) { return savedProtocol(current, id); })) throw new Error(_('Статус основной службы изменился. Дождитесь завершения операции.'));
					if (profilesState.running || profilesState.state === 'pending' || profilesState.state === 'running') throw new Error(_('Дождитесь окончания теста и очистки.'));
					return callProfilesTest(protocol, profiles.join(' '), targets.join(' '), repeat).then(function(reply) {
						requireOK(reply);
						if (reply.pending !== true || !/^[0-9]+\.[0-9]+$/.test(reply.job_id || '')) throw new Error(_('Некорректное подтверждение protocols_test.'));
						profilesJob = reply.job_id;
						jobPlan = { job_id: reply.job_id, protocol: protocol, profiles: profiles.slice(), targets: targets.slice(), repeat: repeat };
						profilesState = { job_id: reply.job_id, protocol: protocol, state: 'pending', running: true, results: [] };
						showProfiles();
					});
				}).catch(function(error) { failure = error; }).then(function() {
					return refreshProfiles().catch(function(error) { failure = failure ? new Error(failure.message + '\n' + error.message) : error; });
				}).finally(function() {
					if (failure) profilesError = failure;
					profilesLaunching = false;
					showProfiles();
				});
			}
		}, _('Начать тест'));
		var applyCandidate = protocolElement('select', { id: 'zapret2-apply-profile', 'class': 'cbi-input-select', style: 'max-width:100%', 'aria-describedby': 'zapret2-apply-hint', change: stage }, [protocolElement('option', { value: '' }, _('Выключено'))].concat(profileIds.map(function(id) { return protocolElement('option', { value: id }, profileLabel(id)); })));
		applyCandidate.value = '';
		var applyButton = button(protocol === 'tcp' ? 'zapret2-profiles-apply' : 'zapret2-' + protocol + '-profiles-apply', _('Применить'), function() {
			var candidate = applyCandidate.value, enabled = candidate !== '', accepted;
			profilesEpoch++;
			return write(Promise.all([refresh(), refreshProfiles()]).then(function() {
				if (mainBlocked() || profilesBlocked() || profilesLaunching || !protocolIds.every(function(id) { return savedProtocol(current, id); }) || !enabled && protocolIds.every(function(id) { return id === protocol || !savedProtocol(current, id).enabled; }) || enabled && profileIds.indexOf(candidate) === -1 || enabled === savedProtocol(current, protocol).enabled && (!enabled || candidate === savedProtocol(current, protocol).profile))
					throw new Error(_('Дождитесь достоверного свободного статуса и выберите другой профиль.'));
				if (!enabled) candidate = savedProtocol(current, protocol).profile;
				return callProfilesApply(protocol, enabled, candidate).then(function(reply) {
					requireOK(reply);
					if (reply.pending != null && typeof reply.pending !== 'boolean' || !/^[0-9]+$/.test(String(reply.job_id || ''))) throw new Error(_('Некорректный ответ protocols_apply.'));
					accepted = reply;
					return awaitConfigure(reply);
				});
			})).then(function() {
				// A later list update blocks new writes, not confirmation of this committed job.
				if (!current || current.configure_recovery_required !== false || !protocolIds.every(function(id) { return savedProtocol(current, id); }) || savedProtocol(current, protocol).profile !== candidate || savedProtocol(current, protocol).enabled !== enabled ||
					current.configure_pending !== false || String(current.configure_job_id) !== String(accepted.job_id) || !current.configure_result || String(current.configure_result.job_id) !== String(accepted.job_id) || current.configure_result.ok !== true)
					throw new Error(_('Применение не подтверждено: проверьте сохранённый выбор и завершение задания.'));
			});
		});
		var profilesPane = protocolElement('div', { id: 'zapret2-protocol-panel', role: 'region', 'aria-labelledby': 'zapret2-protocol-heading' }, [
			protocolElement('h3', { id: 'zapret2-protocol-heading' }, group.title),
			protocolElement('p', {}, group.description),
			protocolElement('section', { 'class': 'z2-stage', 'aria-labelledby': 'zapret2-profile-stage-current' }, [
				protocolElement('h3', { id: 'zapret2-profile-stage-current' }, _('1. Сохранённый профиль')),
				protocolElement('p', {}, [activeProfile, protocolElement('br'), savedProfileHint]),
				advanced(_('О стратегиях и ограничениях теста'), [
					protocolElement('ul', {}, profileIds.map(function(id) {
						var item = group.profiles.filter(function(entry) { return entry.id === id; })[0];
						return protocolElement('li', {}, [protocolElement('strong', {}, profileLabel(id)), ' — ' + profileNotes[id], item && typeof item.strategy === 'string' ? protocolElement('div', { style: 'overflow-wrap:anywhere' }, item.strategy) : '']);
					})),
					protocolElement('p', {}, (protocol === 'tcp' ? _('До 60 проверок, лимит 1350 секунд; тест может занимать канал связи (до 64 КиБ/с). Успех — полная загрузка с проверкой содержимого, TLS и маршрута, не просто HTTP 200.') : protocol === 'quic' ? _('Только изображение YouTube через HTTP/3 без отката на TCP; проверяются TLS, содержимое и прямой маршрут. Это не тест видео.') : _('Успех — строгий STUN-ответ с проверкой транзакции и прямого WAN-адреса. Он не подтверждает голосовую связь.')) + ' ' + _('Только фиксированные ресурсы через прямой IPv4. Тест через туннель не считается прямым обходом. Ошибка соединения не доказывает причину блокировки.'))
				])
			]),
			protocolElement('section', { 'class': 'z2-stage', 'aria-labelledby': 'zapret2-profile-stage-test' }, [
				protocolElement('h3', { id: 'zapret2-profile-stage-test' }, _('2. Выберите, проверьте и сравните')),
				protocolElement('fieldset', {}, [protocolElement('legend', {}, _('Профили для теста')), profileChoices(profileIds, profileInputs, 'profile')]),
				protocolElement('fieldset', {}, [protocolElement('legend', {}, _('Сервисы')), profileChoices(targetIds, targetInputs, 'target')]),
				protocolElement('div', { 'class': 'z2-actions' }, [protocolElement('label', { 'for': 'zapret2-test-repeat' }, _('Повторы:')), profilesRepeat, profilesStart]),
				selectionHint, testHint, progressPanel, profilesResults,
				advanced(_('Технические детали попыток'), [technicalOutput]),
				protocolElement('p', { 'class': 'z2-muted' }, protocol === 'tcp' ? _('YouTube — изображение TCP, Discord — CSS TCP; видео, gateway и голосовая связь не проверены.') : protocol === 'quic' ? _('YouTube — изображение HTTP3, НЕ видео. Экспериментальный профиль не гарантирует работу приложения.') : _('STUN — НЕ голос. Реальную голосовую связь проверьте вручную с собеседником; автоматического подтверждения нет.'))
			]),
			protocolElement('section', { 'class': 'z2-stage', 'aria-labelledby': 'zapret2-profile-stage-apply' }, [
				protocolElement('h3', { id: 'zapret2-profile-stage-apply' }, _('3. Примените вручную')),
				protocolElement('div', { 'class': 'z2-actions' }, [protocolElement('label', { 'for': 'zapret2-apply-profile' }, _('Профиль:')), applyCandidate, applyButton]), applyHint,
				protocolElement('p', { 'class': 'z2-muted' }, _('Применение перезапустит только запущенную службу; остановленная не запускается. Несохранённые настройки формы не применяются.'))
			])
		]);
		protocolViews.push({ sync: syncBranchControls, show: showBranch });
		return profilesPane;
		}
		var catalogGroups = profilesAvailable ? data.profilesCatalog.groups : protocolIds.map(function(id) {
			return { id: id, title: id === 'tcp' ? 'TCP / HTTPS' : id === 'quic' ? 'QUIC' : 'UDP / голос', description: _('Управление недоступно: обновите пакет zapret2-home и ACL LuCI, затем перезагрузите страницу.'), profiles: [], targets: [], test_supported: false, test_unavailable_reason: _('Возможности роутера не подтверждены.') };
		});
		var panels = catalogGroups.map(buildProtocol);
		function chooseProtocol(index) {
			panels.forEach(function(panel, i) { panel.hidden = i !== index; panel.style.display = i === index ? '' : 'none'; protocolButtons[i].setAttribute('aria-pressed', i === index ? 'true' : 'false'); });
		}
		var protocolButtons = catalogGroups.map(function(group, index) {
			return E('button', { id: 'zapret2-protocol-' + group.id, type: 'button', 'class': 'cbi-button', 'aria-pressed': index === 0 ? 'true' : 'false', 'aria-controls': group.id === 'tcp' ? 'zapret2-protocol-panel' : 'zapret2-' + group.id + '-protocol-panel', click: function() { chooseProtocol(index); } }, group.id === 'tcp' ? 'TCP / HTTPS' : group.id === 'quic' ? 'QUIC' : _('UDP / голос'));
		});
		var profilesPane = E('div', { 'class': 'cbi-tab-container', 'data-tab': 'profiles', 'data-tab-title': _('Профили') }, [
			E('style', {}, '#zapret2-home .z2-stage{margin:.75rem 0 1.25rem;min-width:0;padding:0}#zapret2-home .z2-stage p{margin:.5rem 0}#zapret2-home .z2-stage h3{margin:0 0 .5rem}#zapret2-home .z2-muted{opacity:.75;font-size:.9em}#zapret2-home .z2-choices{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,17rem),1fr));gap:.5rem 1rem}#zapret2-home .z2-choices-target{display:flex;flex-wrap:wrap}#zapret2-home .z2-choices label{display:flex;align-items:baseline;gap:.3rem;min-width:0;cursor:pointer}#zapret2-home .z2-actions{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem}#zapret2-home .z2-stage fieldset{min-width:0;margin:.5rem 0 .75rem;padding:0;border:0}#zapret2-home .z2-stage legend{font-size:1em;font-weight:bold;margin:0 0 .4rem}#zapret2-home .z2-matrix{width:100%;table-layout:fixed}#zapret2-home .z2-matrix th,#zapret2-home .z2-matrix td{text-align:left;white-space:normal;overflow-wrap:anywhere;padding:.5rem;vertical-align:top}#zapret2-home .z2-matrix th:first-child{width:24%}#zapret2-home .z2-matrix caption{text-align:left;margin:.5rem 0}#zapret2-home .z2-progress{margin:.75rem 0;padding:.75rem;border:1px solid #aaa;border-left:4px solid currentColor;border-radius:3px}#zapret2-home .z2-progress [role="status"]{font-weight:bold}#zapret2-home .z2-service{display:none}#zapret2-home .z2-cell[data-result="success"]{font-weight:bold}#zapret2-home button:focus-visible,#zapret2-home .z2-stage :focus-visible{outline:2px solid currentColor;outline-offset:2px}#zapret2-home button[aria-pressed="true"]{font-weight:bold;outline:2px solid currentColor;outline-offset:1px}@media(max-width:700px){#zapret2-home .z2-matrix,#zapret2-home .z2-matrix tbody{display:block}#zapret2-home .z2-matrix thead{display:none}#zapret2-home .z2-matrix tbody tr{display:block;margin:.75rem 0;padding:.5rem;border:1px solid #aaa;border-radius:3px}#zapret2-home .z2-matrix th:first-child{display:block;width:auto;padding:.25rem}#zapret2-home .z2-matrix td{display:grid;grid-template-columns:5rem minmax(0,1fr);gap:.5rem;padding:.3rem .25rem}#zapret2-home .z2-service{display:inline}#zapret2-home .z2-matrix caption{display:block;width:100%;box-sizing:border-box}}'),
			E('h3', {}, _('Сохранённые настройки протоколов')), summaryState,
			E('div', { id: 'zapret2-protocol-summary', style: 'display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,16rem),1fr));gap:.5rem;margin-bottom:1rem;overflow-wrap:anywhere' }, catalogGroups.map(function(group) {
				protocolSummaries[group.id] = E('span', { id: 'zapret2-summary-' + group.id });
				return E('div', {}, [E('strong', {}, group.id.toUpperCase() + ': '), protocolSummaries[group.id]]);
			})),
			E('p', { 'class': 'z2-muted' }, _('Это сохранённые настройки, не проверка работы приложений. При остановленной службе профили не работают. «Остановить всё» останавливает всю службу; выключение одного протокола не отключает остальные.')),
			E('div', { role: 'group', 'aria-label': _('Выбор протокола'), style: 'display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem' }, protocolButtons)
		].concat(panels));
		chooseProtocol(0);
		var panes = [settings, diagnostics, journal, profilesPane];
		var tree = E('div', { 'class': 'cbi-map', id: 'zapret2-home' }, [
			E('h2', {}, 'zapret2-home'),
			E('div', { 'class': 'cbi-section', style: 'display:flex;flex-wrap:wrap;align-items:center;gap:.5rem' }, [fields.running, startButton, stopButton, restartButton]),
			message,
			E('div', { 'class': 'cbi-section' }, panes)
		]);
		ui.tabs.initTabGroup(panes);
		setMessage('', false);
		if (initial) applyStatus(initial);
		else {
			fields.running.textContent = _('Состояние неизвестно: status недоступен');
			fields.process.textContent = _('Неизвестно: status недоступен');
			fail(data.error || new Error(_('Статус не получен.')));
			syncControls();
		}
		poll.add(function() {
			if (busy || pollPending) return Promise.resolve();
			pollPending = true;
			return refresh().catch(fail).finally(function() { pollPending = false; });
		}, 5);
		showProfiles();
		poll.add(function() {
			if (profilesLaunching || profilesPolling || profilesKnown && profilesAvailable && profilesState && !profilesState.running && profilesState.state !== 'pending' && profilesState.state !== 'running') return Promise.resolve();
			profilesPolling = true;
			return refreshProfiles().catch(function() {}).finally(function() { profilesPolling = false; });
		}, 1);
		return tree;
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
