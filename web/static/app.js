const form = document.querySelector('#audit-form');
const configInput = document.querySelector('#nginx-config');
const dropzone = document.querySelector('#dropzone');
const errorBox = document.querySelector('#form-error');
const reportEl = document.querySelector('#report');
let currentReport = null;

function setConfigLabel(file) {
  document.querySelector('#config-title').textContent = file ? file.name : 'Загрузите nginx.conf';
  document.querySelector('#config-meta').textContent = file ? `${(file.size / 1024).toFixed(1)} КБ · готов к проверке` : 'или вывод nginx -T · UTF-8 · до 5 МБ';
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
function esc(value) { const div = document.createElement('div'); div.textContent = String(value ?? ''); return div.innerHTML; }

function render(report) {
  currentReport = report;
  document.querySelector('#score').textContent = report.score;
  document.querySelector('#score-label').textContent = report.score >= 90 ? 'Хорошая конфигурация' : report.score >= 70 ? 'Требует внимания' : 'Высокий риск';
  ['critical','high','medium','low'].forEach(level => document.querySelector(`#count-${level}`).textContent = report.summary[level] || 0);
  document.querySelector('#findings-total').textContent = report.findings.length;
  document.querySelector('#resources-total').textContent = report.resources.length;
  document.querySelector('#generated-at').textContent = `Сформирован ${new Date(report.generated_at).toLocaleString('ru-RU')}`;

  document.querySelector('#findings-body').innerHTML = report.findings.map(item => `<tr>
    <td><span class="badge ${esc(item.severity)}">${esc(severityName(item.severity))}</span></td>
    <td><b>${esc(item.message)}</b><small>${esc(item.rule)}</small></td>
    <td class="mono">${esc(item.resource)}</td><td class="evidence">${esc(item.evidence || '—')}</td></tr>`).join('');
  document.querySelector('#findings-empty').hidden = report.findings.length > 0;

  document.querySelector('#visibility-body').innerHTML = report.resources.map(item => {
    const addresses = Object.entries(item.addresses || {}).map(([zone, ips]) => `${zoneName(zone)}: ${(ips || []).join(', ') || '—'}`).join('<br>');
    return `<tr><td><b>${esc(item.name)}</b><small>${esc(item.id)} · ${esc(item.owner)}</small></td>
      <td>${item.expected_visibility.map(zoneName).join(', ') || '—'}</td><td>${item.actual_visibility.map(zoneName).join(', ') || '—'}</td>
      <td class="mono">${addresses}</td><td><span class="status ${esc(item.status)}">${esc(statusName(item.status))}</span></td></tr>`;
  }).join('');
  document.querySelector('#visibility-empty').hidden = report.resources.length > 0;
  reportEl.hidden = false; reportEl.scrollIntoView({behavior:'smooth', block:'start'});
}

form.addEventListener('submit', async event => {
  event.preventDefault(); errorBox.hidden = true;
  const button = form.querySelector('.run'); const label = document.querySelector('#run-label');
  button.disabled = true; label.textContent = 'Анализируем…';
  try {
    const response = await fetch('/api/analyze', {method:'POST', body:new FormData(form)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Не удалось выполнить анализ');
    render(data);
  } catch (error) { errorBox.textContent = error.message; errorBox.hidden = false; }
  finally { button.disabled = false; label.textContent = 'Запустить анализ'; }
});

document.querySelectorAll('.tabs button').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.tabs button').forEach(item => item.classList.toggle('active', item === button));
  document.querySelector('#findings-panel').hidden = button.dataset.tab !== 'findings';
  document.querySelector('#visibility-panel').hidden = button.dataset.tab !== 'visibility';
}));

function download(name, type, content) { const blob = new Blob([content], {type}); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url); }
document.querySelector('#export-json').addEventListener('click', () => currentReport && download('nginx-scope-report.json','application/json',JSON.stringify(currentReport,null,2)));
document.querySelector('#export-csv').addEventListener('click', () => {
  if (!currentReport) return;
  const quote = value => `"${String(value ?? '').replaceAll('"','""')}"`;
  const rows = [['severity','rule','resource','message','evidence'], ...currentReport.findings.map(x => [x.severity,x.rule,x.resource,x.message,x.evidence || ''])];
  download('nginx-scope-findings.csv','text/csv;charset=utf-8','\ufeff' + rows.map(row => row.map(quote).join(',')).join('\n'));
});

