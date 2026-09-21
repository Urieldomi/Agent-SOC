let state = window.INITIAL_STATE;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showError(message) {
  document.querySelector('.toast')?.remove();
  const toast = element('div', 'toast', message);
  document.body.append(toast);
  setTimeout(() => toast.remove(), 4000);
}

async function post(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'No se pudo completar la acción.');
  state = result;
  render();
}

function renderStage(stage) {
  const card = element('article', 'result-card');
  const header = element('div', 'result-header');
  header.append(element('span', 'result-index', String(stage.number).padStart(2, '0')));
  const title = element('div');
  title.append(element('h3', '', stage.agent), element('p', '', stage.summary));
  header.append(title, element('span', 'result-status', '● COMPLETADO'));
  card.append(header);

  const body = element('div', 'result-body');
  const factsPanel = element('div');
  factsPanel.append(element('h4', '', 'EVIDENCIA / DECISIÓN'));
  const facts = element('div', 'facts');
  stage.facts.forEach(([label, value]) => {
    const row = element('div', 'fact');
    row.append(element('span', '', label), element('span', '', value));
    facts.append(row);
  });
  factsPanel.append(facts);
  const logPanel = element('div');
  logPanel.append(element('h4', '', 'REGISTRO DE EJECUCIÓN · SIMULADO'));
  const terminal = element('div', 'terminal');
  stage.logs.forEach(line => terminal.append(element('div', '', line)));
  logPanel.append(terminal);
  body.append(factsPanel, logPanel);
  card.append(body);

  if (stage.finding) card.append(element('div', 'finding', stage.finding));
  if (stage.sources) {
    const sources = element('div', 'source-list');
    stage.sources.forEach(source => {
      const link = element('a', '', source.name);
      link.href = source.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.append(element('small', '', source.detail));
      sources.append(link);
    });
    card.append(sources);
  }
  return card;
}

function render() {
  document.querySelectorAll('[data-scenario]').forEach(button => {
    const selected = button.dataset.scenario === state.scenario;
    button.classList.toggle('selected', selected);
    button.setAttribute('aria-pressed', String(selected));
  });
  document.querySelectorAll('.step-card').forEach(card => {
    const number = Number(card.dataset.step);
    const complete = number <= state.step;
    const ready = number === state.step + 1;
    card.classList.toggle('complete', complete);
    card.classList.toggle('ready', ready);
    card.querySelector('.step-state').textContent = complete ? 'COMPLETADO' : ready ? 'DISPONIBLE' : 'BLOQUEADO';
    const button = card.querySelector('.step-button');
    button.disabled = !ready;
    button.innerHTML = complete ? 'Completado ✓' : `Iniciar agente <span>→</span>`;
  });
  document.getElementById('run-counter').textContent = `${state.step} DE 3 ETAPAS`;
  document.getElementById('empty-state').hidden = state.step > 0;
  document.getElementById('empty-state').style.display = state.step > 0 ? 'none' : '';
  const results = document.getElementById('results');
  results.replaceChildren(...state.stages.map(renderStage));
  document.getElementById('report-action').hidden = state.step !== 3;
}

document.querySelectorAll('[data-scenario]').forEach(button => {
  button.addEventListener('click', () => post('/api/scenario', { scenario: button.dataset.scenario }).catch(error => showError(error.message)));
});
document.querySelectorAll('[data-run]').forEach(button => {
  button.addEventListener('click', () => post(`/api/run/${button.dataset.run}`).catch(error => showError(error.message)));
});
document.getElementById('reset-button').addEventListener('click', () => post('/api/reset').catch(error => showError(error.message)));
render();
