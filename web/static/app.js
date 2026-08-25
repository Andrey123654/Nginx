const form = document.querySelector('#audit-form');
const configInput = document.querySelector('#nginx-config');
const dropzone = document.querySelector('#dropzone');
const errorBox = document.querySelector('#form-error');
const reportEl = document.querySelector('#report');
let currentReport = null;

function setConfigLabel(file) {
  document.querySelector('#config-title').textContent = file ? file.name : 'Загрузите nginx.conf';
  document.querySelector('#config-meta').textContent = file ? `${(file.size / 1024).toFixed(1)} КБ · готов к проверке` : 'или вывод nginx -T, в том числе без расширения · UTF-8 · до 5 МБ';
  dropzone.classList.toggle('selected', Boolean(file));
}

configInput.addEventListener('change', () => setConfigLabel(configInput.files[0]));
['dragenter', 'dragover'].forEach(name => dropzone.addEventListener(name, event => { event.preventDefault(); dropzone.classList.add('dragging'); }));
['dragleave', 'drop'].forEach(name => dropzone.addEventListener(name, event => { event.preventDefault(); dropzone.classList.remove('dragging'); }));
dropzone.addEventListener('drop', event => {
  const file = event.dataTransfer.files[0];
  if (!file) return;
  const transfer = new DataTransfer(); transfer.items.add(file); configInput.files = transfer.files; setConfigLabel(file);
});

function severityName(value) { return ({critical:'Критический',high:'Высокий',medium:'Средний',low:'Низкий',info:'Инфо'})[value] || value; }
function zoneName(value) { return ({external:'Внешняя',internal:'Внутренняя'})[value] || value; }
function statusName(value) { return ({compliant:'Соответствует',unexpected_exposure:'Лишняя публикация',missing_exposure:'Недоступен',unknown:'Нет данных'})[value] || value; }
function visibilityName(value) { return ({external:'Наружу',internal:'Внутренний контур',local:'Только сервер',unknown:'Требует проверки'})[value] || value; }
function esc(value) { const div = document.createElement('div'); div.textContent = String(value ?? ''); return div.innerHTML; }
function valueText(value) { return Array.isArray(value) ? value.join(', ') || '—' : typeof value === 'boolean' ? (value ? 'да' : 'нет') : String(value ?? '—'); }

function render(report) {
  currentReport = report;
  document.querySelector('#score').textContent = report.score;
  document.querySelector('#score-label').textContent = report.score >= 90 ? 'Хорошая конфигурация' : report.score >= 70 ? 'Требует внимания' : 'Высокий риск';
  ['critical','high','medium','low'].forEach(level => document.querySelector(`#count-${level}`).textContent = report.summary[level] || 0);
  document.querySelector('#findings-total').textContent = report.findings.length;
  document.querySelector('#resources-total').textContent = report.resources.length;
  document.querySelector('#publications-total').textContent = report.publications.length;
  const comparison = report.comparison || {added:[],removed:[],modified:[],status:'not_compared',unchanged:0};
  const changeCount = comparison.added.length + comparison.removed.length + comparison.modified.length;
  document.querySelector('#changes-total').textContent = changeCount;
  document.querySelector('#generated-at').textContent = `Сформирован ${new Date(report.generated_at).toLocaleString('ru-RU')}`;

  document.querySelector('#findings-body').innerHTML = report.findings.map(item => `<tr>
    <td><span class="badge ${esc(item.severity)}">${esc(severityName(item.severity))}</span></td>
    <td><b>${esc(item.message)}</b><small>${esc(item.rule)}</small></td>
    <td class="recommendation">${esc(item.recommendation || 'Требуется анализ владельцем ресурса')}</td>
    <td class="mono">${esc(item.resource)}</td><td class="evidence">${esc(item.evidence || '—')}</td></tr>`).join('');
  document.querySelector('#findings-empty').hidden = report.findings.length > 0;

  document.querySelector('#publications-list').innerHTML = report.publications.map(item => {
    const declared = (item.declared_visibility || []).map(zone => `<span class="zone-chip ${esc(zone)}">${esc(visibilityName(zone))}</span>`).join('') || '—';
    const actual = (item.actual_visibility || []).map(zone => `<span class="zone-chip ${esc(zone)}">${esc(visibilityName(zone))}</span>`).join('') || 'Нет данных датчиков';
    const addresses = Object.entries(item.addresses || {}).map(([zone, ips]) => `${visibilityName(zone)}: ${(ips || []).join(', ')}`).join('<br>') || '—';
    const findings = item.findings.length ? item.findings.map(finding => `<div class="publication-finding ${esc(finding.severity)}"><b>${esc(finding.message)}</b><span>${esc(finding.recommendation)}</span><small>${esc(finding.control)} · ${esc(finding.rule)}</small></div>`).join('') : '<div class="publication-finding"><b>Локальных замечаний не найдено</b><span>Проверьте общие замечания конфигурации выше.</span></div>';
    const locations = item.locations.length ? `<div class="location-list"><b>Настройки location</b>${item.locations.map(location => `<details><summary>${esc(location.path)}</summary><pre class="config-view">${esc(location.config_excerpt)}</pre></details>`).join('')}</div>` : '';
    return `<article class="publication-card">
      <header class="publication-head"><div><h3>${esc(item.server_names.join(', '))}</h3><p>${esc(item.id)} · строка ${esc(item.line_start)} · ${item.tls ? 'HTTPS/TLS' : 'HTTP'}</p></div><div class="publication-score"><b>${esc(item.score)}</b><span>оценка</span></div></header>
      <div class="publication-meta"><div><b>Listen</b><span>${esc(item.listen.join(', '))}</span></div><div><b>Потенциальная зона</b><span>${declared}</span></div><div><b>Фактически по датчикам</b><span>${actual}</span></div><div><b>Адреса / upstream</b><span>${addresses}<br>${esc(item.upstreams.join(', ') || 'upstream не найден')}</span></div></div>
      <div class="publication-body"><pre class="config-view">${esc(item.config_excerpt)}</pre><div class="publication-findings">${findings}</div></div>${locations}
    </article>`;
  }).join('');
  document.querySelector('#publications-empty').hidden = report.publications.length > 0;

  document.querySelector('#visibility-body').innerHTML = report.resources.map(item => {
    const addresses = Object.entries(item.addresses || {}).map(([zone, ips]) => `${zoneName(zone)}: ${(ips || []).join(', ') || '—'}`).join('<br>');
    return `<tr><td><b>${esc(item.name)}</b><small>${esc(item.id)} · ${esc(item.owner)}</small></td>
      <td>${item.expected_visibility.map(zoneName).join(', ') || '—'}</td><td>${item.actual_visibility.map(zoneName).join(', ') || '—'}</td>
      <td class="mono">${addresses}</td><td><span class="status ${esc(item.status)}">${esc(statusName(item.status))}</span></td></tr>`;
  }).join('');
  document.querySelector('#visibility-empty').hidden = report.resources.length > 0;

  const compareText = comparison.status === 'not_compared' ? 'Эталон не загружен. Сохраните текущий или загрузите ранее сохранённый nginx-baseline.json.' : comparison.status === 'unchanged' ? `Отклонений от эталона нет. Без изменений: ${comparison.unchanged}.` : `Найдены изменения: добавлено ${comparison.added.length}, удалено ${comparison.removed.length}, изменено ${comparison.modified.length}.`;
  document.querySelector('#comparison-summary').innerHTML = `<b>${comparison.status === 'changed' ? 'Обнаружен дрейф конфигурации' : comparison.status === 'unchanged' ? 'Соответствует эталону' : 'Сравнение не выполнено'}</b>${esc(compareText)}`;
  const added = comparison.added.map(item => `<article class="change-card change-added"><h3>Добавлена публикация: ${esc((item.server_names || []).join(', '))}</h3><div>${esc(JSON.stringify(item, null, 2))}</div></article>`);
  const removed = comparison.removed.map(item => `<article class="change-card change-removed"><h3>Удалена публикация: ${esc((item.server_names || []).join(', '))}</h3><div>${esc(JSON.stringify(item, null, 2))}</div></article>`);
  const modified = comparison.modified.map(item => `<article class="change-card change-modified"><h3>Изменена публикация: ${esc((item.server_names || []).join(', '))}</h3>${item.changes.map(change => `<div class="change-row"><b>${esc(change.field)}</b><span>${esc(valueText(change.before))}</span><i>→</i><span>${esc(valueText(change.after))}</span></div>`).join('')}</article>`);
  document.querySelector('#changes-list').innerHTML = [...added, ...removed, ...modified].join('');
  reportEl.hidden = false; reportEl.scrollIntoView({behavior:'smooth', block:'start'});
}

form.addEventListener('submit', async event => {
  event.preventDefault(); errorBox.hidden = true;
  const button = form.querySelector('.run'); const label = document.querySelector('#run-label');
  button.disabled = true; label.textContent = 'Анализируем…';
  try {
    const payload = new FormData();
    const configFile = configInput.files[0];
    if (configFile) payload.append('nginx_config', configFile);
    for (const field of ['inventory', 'external_sensor', 'internal_sensor', 'baseline']) {
      const optionalFile = form.elements[field].files[0];
      if (optionalFile) payload.append(field, optionalFile);
    }
    const response = await fetch('/api/analyze', {method:'POST', body:payload});
    const body = await response.text();
    let data = null;
    try { data = body ? JSON.parse(body) : null; } catch (_) { data = null; }
    if (!response.ok) {
      let reason = {message: `Сервер отклонил файл (HTTP ${response.status})`};
      if (data && typeof data.detail === 'object' && !Array.isArray(data.detail)) reason = data.detail;
      else if (data && typeof data.detail === 'string') reason.message = data.detail;
      else if (Array.isArray(data?.detail)) reason.message = data.detail.map(item => item.msg).join('; ');
      if (response.status === 413 && !reason.hint) reason.hint = 'Файл превышает лимит reverse proxy или приложения';
      const error = new Error(reason.message || 'Не удалось выполнить анализ');
      error.reason = reason;
      throw error;
    }
    render(data);
  } catch (error) {
    const reason = error.reason || {message: error.message};
    errorBox.replaceChildren();
    const title = document.createElement('b'); title.textContent = reason.message || 'Файл отклонён';
    errorBox.appendChild(title);
    if (reason.filename) { const file = document.createElement('span'); file.textContent = `Файл: ${reason.filename}`; errorBox.appendChild(file); }
    if (reason.hint) { const hint = document.createElement('span'); hint.textContent = `Что сделать: ${reason.hint}`; errorBox.appendChild(hint); }
    if (reason.code) { const code = document.createElement('small'); code.textContent = `Код причины: ${reason.code}`; errorBox.appendChild(code); }
    errorBox.hidden = false;
  }
  finally { button.disabled = false; label.textContent = 'Запустить анализ'; }
});

document.querySelectorAll('.tabs button').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.tabs button').forEach(item => item.classList.toggle('active', item === button));
  ['findings','publications','visibility','changes'].forEach(name => { document.querySelector(`#${name}-panel`).hidden = button.dataset.tab !== name; });
}));

function download(name, type, content) { const blob = new Blob([content], {type}); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url); }
document.querySelector('#export-fixed').addEventListener('click', () => currentReport?.corrected_config && download('nginx.corrected.conf','text/plain;charset=utf-8',currentReport.corrected_config));
document.querySelector('#save-baseline').addEventListener('click', () => currentReport?.baseline && download('nginx-baseline.json','application/json;charset=utf-8',JSON.stringify(currentReport.baseline,null,2)));
document.querySelector('#export-json').addEventListener('click', () => {
  if (!currentReport) return;
  const {corrected_config, ...reportWithoutConfig} = currentReport;
  download('nginx-scope-report.json','application/json',JSON.stringify(reportWithoutConfig,null,2));
});
document.querySelector('#export-csv').addEventListener('click', () => {
  if (!currentReport) return;
  const quote = value => `"${String(value ?? '').replaceAll('"','""')}"`;
  const rows = [['severity','rule','resource','message','recommendation','evidence'], ...currentReport.findings.map(x => [x.severity,x.rule,x.resource,x.message,x.recommendation || '',x.evidence || ''])];
  download('nginx-scope-findings.csv','text/csv;charset=utf-8','\ufeff' + rows.map(row => row.map(quote).join(',')).join('\n'));
});
