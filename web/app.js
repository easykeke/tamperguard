'use strict';

/* ==========================================================================
 * TamperGuard 管理端（纯静态单页应用，零依赖）
 *
 * 安全约定：
 * - innerHTML 仅用于本文件内的静态骨架字符串（固定文案与结构，不含任何
 *   API 数据）；所有来自服务端的字符串一律走 textContent，避免 XSS。
 * - 所有请求使用 credentials: 'same-origin'，会话由服务端 HttpOnly Cookie
 *   维持，前端不保存任何凭据。
 * ========================================================================== */

/* --------------------------------------------------------------------------
 * 常量
 * ------------------------------------------------------------------------ */

const API_BASE = '/api/v1';
const PUBLISH_POLL_MS = 5000;

const NAV_ITEMS = [
  { key: 'overview', label: '总览', hash: '#/overview' },
  { key: 'nodes', label: '节点', hash: '#/nodes' },
  { key: 'policies', label: '策略', hash: '#/policies' },
  { key: 'publish', label: '发布', hash: '#/publish' },
  { key: 'audit', label: '审计', hash: '#/audit' },
  { key: 'revocations', label: '吊销', hash: '#/revocations' },
];

const NAV_ACTIVE_MAP = {
  overview: 'overview',
  nodes: 'nodes',
  'node-detail': 'nodes',
  policies: 'policies',
  'policy-new': 'policies',
  'policy-edit': 'policies',
  publish: 'publish',
  audit: 'audit',
  revocations: 'revocations',
};

const ROUTE_TITLES = {
  overview: '总览',
  nodes: '节点',
  'node-detail': '节点详情',
  policies: '策略',
  'policy-new': '新建策略',
  'policy-edit': '编辑策略',
  publish: '发布',
  audit: '审计',
  revocations: '吊销',
  'not-found': '页面不存在',
};

const NODE_STATUS_META = {
  online: { label: '在线', tone: 'ok' },
  offline: { label: '离线', tone: 'muted' },
  uninstalling: { label: '卸载中', tone: 'warn' },
  uninstalled: { label: '已卸载', tone: 'muted' },
};

const ENFORCER_LABELS = {
  'ebpf-lsm': 'eBPF LSM',
  fanotify: 'fanotify',
  observe: 'observe',
};

const NODE_ROLE_LABELS = {
  protect: 'protect（保护节点）',
  publish: 'publish（发布端）',
};

const PUBLISH_STATUS_META = {
  pending: { label: '待处理', tone: 'info' },
  manifest_received: { label: '已收清单', tone: 'info' },
  token_issued: { label: '已签发令牌', tone: 'warn' },
  done: { label: '完成', tone: 'ok' },
  failed: { label: '失败', tone: 'danger' },
  cancelled: { label: '已取消', tone: 'muted' },
};

const PUBLISH_FILTER_STATUSES = [
  'pending',
  'manifest_received',
  'token_issued',
  'done',
  'failed',
  'cancelled',
];

const DECISION_META = {
  deny: { label: '拒绝', tone: 'danger' },
  allow: { label: '放行', tone: 'ok' },
  observe: { label: '观察', tone: 'info' },
};

const REVOCATION_KIND_META = {
  token: { label: '令牌', hint: '填写令牌 ID（token_id）' },
  subject: { label: '主体', hint: '填写发布端 ID 或进程主体标识' },
  node: { label: '节点', hint: '填写节点 ID（n_...）' },
};

/* 与 internal/audit 的事件类型常量保持一致，仅用于筛选下拉。 */
const AUDIT_KINDS = [
  'write.blocked',
  'write.allowed',
  'write.observed',
  'token.issued',
  'token.revoked',
  'token.rejected',
  'policy.applied',
  'enforcer.degraded',
  'enforcer.error',
  'agent.started',
  'agent.heartbeat',
  'publish.completed',
  'publish.failed',
];

const AUDIT_KIND_LABELS = {
  'write.blocked': '写入被拦截',
  'write.allowed': '写入被放行',
  'write.observed': '写入被观察',
  'token.issued': '令牌签发',
  'token.revoked': '令牌吊销',
  'token.rejected': '令牌被拒',
  'policy.applied': '策略应用',
  'enforcer.degraded': '防护降级',
  'enforcer.error': '防护异常',
  'agent.started': 'Agent 启动',
  'agent.heartbeat': 'Agent 心跳',
  'publish.completed': '发布完成',
  'publish.failed': '发布失败',
  'publish.file': '发布文件写入',
  'tamper.restored': '篡改已恢复',
  'agent.selfcheck_failed': 'Agent 自检失败',
  'uninstall.requested': '卸载请求',
  'uninstall.approved': '卸载批准',
  'uninstall.denied': '卸载拒绝',
  'uninstall.completed': '卸载完成',
};

const ERROR_CODE_LABELS = {
  unauthorized: '登录状态已失效，请重新登录。',
  forbidden: '没有权限执行该操作。',
  not_found: '请求的资源不存在。',
  conflict: '操作与当前状态冲突。',
  invalid: '请求参数不合法。',
  internal: '服务端内部错误，请稍后重试。',
  chain_broken: '审计链校验失败。',
  token_expired: '令牌已过期。',
  revoked: '对象已被吊销。',
  degraded_not_approved: '节点降级防护未获批准。',
};

/* --------------------------------------------------------------------------
 * 静态骨架（仅固定结构，绝无动态数据）
 * ------------------------------------------------------------------------ */

const SHELL_HTML = `
<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      <span class="brand__mark" aria-hidden="true">TG</span>
      <span class="brand__text">
        <span class="brand__name">TamperGuard</span>
        <span class="brand__sub">网页防篡改系统</span>
      </span>
    </div>
    <nav class="nav" id="nav" aria-label="主导航"></nav>
    <div class="sidebar__foot">
      <span class="mono">API v1</span>
      <span>管理端</span>
    </div>
  </aside>
  <div class="main-wrap">
    <header class="topbar">
      <div class="topbar__title" id="page-title"></div>
      <div class="topbar__user">
        <span class="user-chip">
          <span class="user-chip__name" id="user-name"></span>
          <span class="user-chip__role" id="user-role"></span>
        </span>
        <button type="button" class="btn btn--sm" id="theme-btn" title="切换主题">主题</button>
        <button type="button" class="btn btn--sm" id="password-btn">修改密码</button>
        <button type="button" class="btn btn--sm" id="logout-btn">退出登录</button>
      </div>
    </header>
    <main class="content" id="view"></main>
  </div>
</div>`;

const LOGIN_HTML = `
<div class="login-screen">
  <div class="login-card">
    <div class="login-brand">
      <span class="brand__mark" aria-hidden="true">TG</span>
      <div>
        <h1 class="login-title">TamperGuard 管理端</h1>
        <p class="login-sub">网页防篡改系统</p>
      </div>
    </div>
    <form id="login-form" class="login-form" novalidate>
      <label class="field">
        <span class="label">用户名</span>
        <input id="login-username" class="input" type="text" name="username"
               autocomplete="username" spellcheck="false" autofocus>
      </label>
      <label class="field">
        <span class="label">密码</span>
        <input id="login-password" class="input" type="password" name="password"
               autocomplete="current-password">
      </label>
      <div id="login-error" class="login-error hidden" role="alert"></div>
      <button id="login-submit" class="btn btn--primary btn--block" type="submit">登录</button>
    </form>
    <p id="login-boot-note" class="login-note login-note--warn hidden"></p>
    <p class="login-note">仅限授权运维人员使用。登录会话通过 HttpOnly Cookie 维持，前端不保存凭据；所有操作均写入审计日志。</p>
  </div>
</div>`;

const PUBLISH_FORM_HTML = `
<form id="pub-form" class="pub-form" novalidate>
  <div id="pub-form-error" class="notice notice--danger hidden" role="alert"></div>
  <div id="pub-nodes-error" class="notice notice--warn hidden"></div>
  <div class="form-grid">
    <div class="field">
      <label class="label" for="pub-node">目标节点 <span class="req">*</span></label>
      <select id="pub-node" class="select"></select>
      <p class="field-error hidden" data-error-for="node_id"></p>
    </div>
    <div class="field">
      <label class="label" for="pub-publisher">发布端 <span class="req">*</span></label>
      <select id="pub-publisher" class="select"></select>
      <p class="field-error hidden" data-error-for="publisher_id"></p>
    </div>
    <div class="field">
      <label class="label" for="pub-delivery">发布方式</label>
      <select id="pub-delivery" class="select">
        <option value="local">本机写入（发布端与目标同机，或发布端可写目标目录）</option>
        <option value="pull">跨机拉取（发布端上传制品，目标节点拉取安装）</option>
      </select>
      <p class="field-hint muted">跨机发布时，选择 pull：制品传到控制面，目标节点拉取并校验后安装。</p>
    </div>
    <div class="field">
      <label class="label" for="pub-mode">同步模式</label>
      <select id="pub-mode" class="select">
        <option value="full">全量（写入源目录所有文件）</option>
        <option value="incremental">增量（仅写入哈希变化的文件）</option>
      </select>
      <p class="field-hint muted">增量模式按 SHA-256 比对目标/上次发布，未变化的文件跳过；文件内容始终逐个哈希校验。</p>
    </div>
    <div class="field">
      <label class="label" for="pub-source">源目录 <span class="req">*</span></label>
      <input id="pub-source" class="input" type="text" spellcheck="false"
             autocomplete="off" placeholder="如 /var/www/releases/v42">
      <p class="field-error hidden" data-error-for="source_dir"></p>
    </div>
    <div class="field">
      <label class="label" for="pub-target">目标目录 <span class="req">*</span></label>
      <input id="pub-target" class="input" type="text" spellcheck="false"
             autocomplete="off" placeholder="如 /var/www/site">
      <p class="field-error hidden" data-error-for="target_dir"></p>
    </div>
    <div class="field">
      <label class="label" for="pub-note">备注</label>
      <input id="pub-note" class="input" type="text" maxlength="200"
             placeholder="可选，本次发布说明">
    </div>
  </div>
  <div class="form-actions form-actions--inline">
    <button id="pub-submit" class="btn btn--primary" type="submit">创建请求</button>
  </div>
</form>`;

const SYNC_PROFILE_HTML = `
<form id="sync-form" class="sync-form" novalidate>
  <div class="form-grid">
    <div class="field">
      <label class="label" for="sp-publisher">发布端 <span class="req">*</span></label>
      <select id="sp-publisher" class="select"></select>
    </div>
    <div class="field">
      <label class="label" for="sp-node">目标节点 <span class="req">*</span></label>
      <select id="sp-node" class="select"></select>
    </div>
    <div class="field">
      <label class="label" for="sp-source">源目录 <span class="req">*</span></label>
      <input id="sp-source" class="input" type="text" spellcheck="false" placeholder="发布端主机上的目录，如 /srv/release">
    </div>
    <div class="field">
      <label class="label" for="sp-target">目标目录 <span class="req">*</span></label>
      <input id="sp-target" class="input" type="text" spellcheck="false" placeholder="被保护主机上的目录，如 /var/www/site">
    </div>
    <div class="field">
      <label class="label" for="sp-mode">模式</label>
      <select id="sp-mode" class="select">
        <option value="full">全量</option>
        <option value="incremental">增量</option>
      </select>
    </div>
    <div class="field">
      <label class="label" for="sp-delivery">方式</label>
      <select id="sp-delivery" class="select">
        <option value="pull">跨机拉取</option>
        <option value="local">本机写入</option>
      </select>
    </div>
  </div>
  <div class="form-actions form-actions--inline">
    <button id="sp-save" class="btn btn--primary" type="submit">保存同步配置</button>
  </div>
</form>`;

const REVOCATION_FORM_HTML = `
<form id="rev-form" class="rev-form" novalidate>
  <div id="rev-form-error" class="notice notice--danger hidden" role="alert"></div>
  <div class="form-grid">
    <div class="field">
      <label class="label" for="rev-kind">类型 <span class="req">*</span></label>
      <select id="rev-kind" class="select">
        <option value="token">token（令牌）</option>
        <option value="subject">subject（主体）</option>
        <option value="node">node（节点）</option>
      </select>
    </div>
    <div class="field">
      <label class="label" for="rev-value">值 <span class="req">*</span></label>
      <input id="rev-value" class="input" type="text" spellcheck="false" autocomplete="off">
      <p class="field-error hidden" data-error-for="value"></p>
      <p id="rev-kind-hint" class="field-hint"></p>
    </div>
    <div class="field">
      <label class="label" for="rev-reason">原因 <span class="req">*</span></label>
      <input id="rev-reason" class="input" type="text" maxlength="200"
             placeholder="如：令牌疑似泄露">
      <p class="field-error hidden" data-error-for="reason"></p>
    </div>
  </div>
  <div class="form-actions form-actions--inline">
    <button id="rev-submit" class="btn btn--primary" type="submit">提交吊销</button>
  </div>
</form>`;

const AUDIT_FILTER_HTML = `
<div class="filter">
  <label class="filter__label" for="aud-node">节点</label>
  <select id="aud-node" class="select select--auto"></select>
</div>
<div class="filter">
  <label class="filter__label" for="aud-kind">类型</label>
  <select id="aud-kind" class="select select--auto"></select>
</div>
<div class="filter">
  <label class="filter__label" for="aud-limit">条数</label>
  <select id="aud-limit" class="select select--auto">
    <option value="20">20</option>
    <option value="50" selected>50</option>
    <option value="100">100</option>
    <option value="200">200</option>
  </select>
</div>
<div class="filter__spacer"></div>
<button id="aud-verify" class="btn" type="button">验证审计链</button>
<button id="aud-refresh" class="btn btn--ghost" type="button">刷新</button>
<p id="aud-node-hint" class="filter__hint hidden"></p>`;

/* --------------------------------------------------------------------------
 * 全局状态
 * ------------------------------------------------------------------------ */

const state = {
  me: null,
  bootError: null,
  pendingHash: null,
  authNotified: false,
  currentView: null,
  drawer: null,
  modal: null,
};

/* --------------------------------------------------------------------------
 * 基础工具
 * ------------------------------------------------------------------------ */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node && node.firstChild) node.removeChild(node.firstChild);
  return node;
}

function textOr(value, fallback) {
  const fb = fallback === undefined ? '—' : fallback;
  if (value === undefined || value === null) return fb;
  const text = String(value).trim();
  return text === '' ? fb : text;
}

function pad2(value) {
  return String(value).padStart(2, '0');
}

/* Unix 秒 → 本地 YYYY-MM-DD HH:mm:ss */
function fmtTime(seconds) {
  const num = Number(seconds);
  if (!Number.isFinite(num) || num <= 0) return '—';
  const date = new Date(num * 1000);
  if (Number.isNaN(date.getTime())) return '—';
  return (
    date.getFullYear() +
    '-' + pad2(date.getMonth() + 1) +
    '-' + pad2(date.getDate()) +
    ' ' + pad2(date.getHours()) +
    ':' + pad2(date.getMinutes()) +
    ':' + pad2(date.getSeconds())
  );
}

/* 心跳时间的相对描述，放在绝对时间下方作为辅助信息 */
function fmtAgo(seconds) {
  const num = Number(seconds);
  if (!Number.isFinite(num) || num <= 0) return '';
  const diff = Math.floor(Date.now() / 1000) - num;
  if (diff < 0) return '';
  if (diff < 5) return '刚刚';
  if (diff < 60) return diff + ' 秒前';
  if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
  if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
  return Math.floor(diff / 86400) + ' 天前';
}

function clockNow() {
  const now = new Date();
  return pad2(now.getHours()) + ':' + pad2(now.getMinutes()) + ':' + pad2(now.getSeconds());
}

/* 长 ID / 摘要的中间省略展示，完整值保留在 title 中 */
function shortId(value, head, tail) {
  const text = value === undefined || value === null ? '' : String(value);
  if (!text) return '—';
  const h = head === undefined ? 10 : head;
  const t = tail === undefined ? 6 : tail;
  if (text.length <= h + t + 1) return text;
  return text.slice(0, h) + '…' + text.slice(-t);
}

function metricNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? String(Math.trunc(num)) : '—';
}

function isAborted(err) {
  return Boolean(err) && (err.kind === 'aborted' || err.name === 'AbortError');
}

function enforcerLabel(value) {
  const raw = textOr(value);
  return ENFORCER_LABELS[raw] || raw;
}

function degradedInfo(node) {
  if (!node || !node.degraded) return { label: '正常', tone: 'ok' };
  return node.degraded_approved
    ? { label: '已降级（已批准）', tone: 'warn' }
    : { label: '已降级（待审批）', tone: 'danger' };
}

/* 吊销记录的时间字段未在本版 API 文档中固定命名，兼容常见写法，缺失时显示占位 */
function pickTimestamp(obj) {
  if (!obj || typeof obj !== 'object') return 0;
  const keys = ['created_at', 'revoked_at', 'ts', 'time'];
  for (let i = 0; i < keys.length; i += 1) {
    const value = obj[keys[i]];
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return 0;
}

function setHash(hash, replace) {
  if (location.hash === hash) return;
  if (replace) location.replace(hash);
  else location.hash = hash;
}

/* --------------------------------------------------------------------------
 * Toast 通知
 * ------------------------------------------------------------------------ */

function toast(message, tone) {
  const container = document.getElementById('toasts');
  if (!container) return;
  const type = tone === 'success' || tone === 'error' ? tone : 'info';
  const box = el('div', 'toast toast--' + type);
  box.setAttribute('role', type === 'error' ? 'alert' : 'status');
  const msg = el('div', 'toast__msg', textOr(message, '操作失败。'));
  const closeBtn = el('button', 'toast__close', '×');
  closeBtn.type = 'button';
  closeBtn.setAttribute('aria-label', '关闭提示');
  closeBtn.addEventListener('click', function () {
    box.remove();
  });
  box.append(msg, closeBtn);
  container.appendChild(box);
  while (container.children.length > 4) {
    container.removeChild(container.firstElementChild);
  }
  const ttl = type === 'error' ? 6500 : 4000;
  setTimeout(function () {
    if (box.isConnected) box.remove();
  }, ttl);
}

/* --------------------------------------------------------------------------
 * HTTP 封装
 * ------------------------------------------------------------------------ */

function buildQuery(query) {
  if (!query) return '';
  const params = new URLSearchParams();
  Object.keys(query).forEach(function (key) {
    const value = query[key];
    if (value === undefined || value === null || value === '') return;
    params.set(key, String(value));
  });
  const text = params.toString();
  return text ? '?' + text : '';
}

class ApiError extends Error {
  constructor(kind, message, status, code) {
    super(message || '请求失败。');
    this.name = 'ApiError';
    this.kind = kind;
    this.status = status || 0;
    this.code = code || '';
    this.handled = false;
  }
}

function errorTextFromBody(body, status) {
  if (body && typeof body === 'object') {
    if (typeof body.message === 'string' && body.message.trim()) return body.message.trim();
    if (typeof body.error === 'string') {
      if (ERROR_CODE_LABELS[body.error]) return ERROR_CODE_LABELS[body.error];
      if (body.error.trim()) return '请求失败：' + body.error.trim();
    }
  }
  if (status === 401) return '登录状态已失效，请重新登录。';
  if (status === 403) return '没有权限执行该操作。';
  if (status === 404) return '请求的资源不存在。';
  if (status === 409) return '操作与当前状态冲突。';
  if (status === 400 || status === 422) return '请求参数不合法。';
  if (status >= 500) return '服务端错误（HTTP ' + status + '），请稍后重试。';
  return '请求失败（HTTP ' + status + '）。';
}

/* 全局 401 处理：清理会话状态并回到登录页，只提示一次 */
function handleSessionExpired() {
  state.me = null;
  if (state.authNotified) return;
  state.authNotified = true;
  toast('登录状态已失效，请重新登录。', 'error');
  if (location.hash === '#/login') {
    handleRoute();
  } else {
    setHash('#/login');
  }
}

async function api(method, path, options) {
  const opts = options || {};
  const upper = String(method || 'GET').toUpperCase();
  const mutating = upper === 'POST' || upper === 'PUT' || upper === 'DELETE';
  const headers = { Accept: 'application/json' };
  // 契约要求所有写操作携带 JSON Content-Type
  if (mutating) headers['Content-Type'] = 'application/json';

  const init = { method: upper, credentials: 'same-origin', headers: headers };
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  if (opts.signal) init.signal = opts.signal;

  let response;
  try {
    response = await fetch(API_BASE + path + buildQuery(opts.query), init);
  } catch (err) {
    if (err && err.name === 'AbortError') throw new ApiError('aborted', '请求已取消。');
    throw new ApiError('network', '无法连接服务端，请确认后端服务已启动。');
  }

  let raw = '';
  try {
    raw = await response.text();
  } catch (err) {
    raw = '';
  }

  let data = null;
  if (raw) {
    try {
      data = JSON.parse(raw);
    } catch (err) {
      if (response.ok) {
        throw new ApiError('parse', '服务端响应无法解析（HTTP ' + response.status + '）。', response.status);
      }
      const parseError = new ApiError('http', '请求失败（HTTP ' + response.status + '）。', response.status);
      if (response.status === 401 && !opts.allow401) {
        handleSessionExpired();
        parseError.handled = true;
      }
      throw parseError;
    }
  }

  if (!response.ok) {
    const code = data && typeof data === 'object' && typeof data.error === 'string' ? data.error : '';
    const httpError = new ApiError('http', errorTextFromBody(data, response.status), response.status, code);
    if (response.status === 401 && !opts.allow401) {
      handleSessionExpired();
      httpError.handled = true;
    }
    throw httpError;
  }

  return data;
}

/* --------------------------------------------------------------------------
 * 通用界面片段
 * ------------------------------------------------------------------------ */

function button(text, options) {
  const opts = options || {};
  const classes = ['btn'];
  if (opts.variant) classes.push('btn--' + opts.variant);
  if (opts.size) classes.push('btn--' + opts.size);
  const node = el('button', classes.join(' '), text);
  node.type = 'button';
  if (opts.title) node.title = String(opts.title);
  if (opts.disabled) node.disabled = true;
  if (typeof opts.onClick === 'function') node.addEventListener('click', opts.onClick);
  return node;
}

function badge(text, tone, title) {
  const node = el('span', 'badge badge--' + (tone || 'muted'), text);
  if (title) node.title = String(title);
  return node;
}

function buildPageHead(options) {
  const opts = options || {};
  const head = el('div', 'page-head');
  const textBox = el('div', 'page-head__text');
  textBox.appendChild(el('h1', 'page-title', opts.title || ''));
  if (opts.desc) textBox.appendChild(el('p', 'page-desc', opts.desc));
  head.appendChild(textBox);
  if (Array.isArray(opts.actions) && opts.actions.length > 0) {
    const actions = el('div', 'page-actions');
    opts.actions.forEach(function (action) {
      if (action) actions.appendChild(action);
    });
    head.appendChild(actions);
  }
  return head;
}

function buildPanel(title, options) {
  const opts = options || {};
  const panel = el('section', 'panel');
  const head = el('div', 'panel__head');
  head.appendChild(el('h2', 'panel__title', title || ''));
  if (opts.meta) head.appendChild(el('span', 'panel__meta', opts.meta));
  if (opts.link) {
    const link = el('a', 'panel__link', opts.link.label);
    link.href = opts.link.href;
    head.appendChild(link);
  }
  if (opts.headNode) head.appendChild(opts.headNode);
  const body = el('div', opts.bodyClass || 'panel__body');
  panel.append(head, body);
  return { panel: panel, head: head, body: body };
}

function createTable(columns, extraClass) {
  const table = el('table', 'data-table' + (extraClass ? ' ' + extraClass : ''));
  const thead = el('thead');
  const headRow = el('tr');
  columns.forEach(function (column) {
    headRow.appendChild(el('th', column.className || '', column.label || ''));
  });
  thead.appendChild(headRow);
  const tbody = el('tbody');
  table.append(thead, tbody);
  return { table: table, thead: thead, tbody: tbody };
}

function cell(value, className, title) {
  const node = el('td', className || '', textOr(value));
  if (title) node.title = String(title);
  return node;
}

function cellNode(child, className) {
  const node = el('td', className || '');
  node.appendChild(child);
  return node;
}

function loadingBlock(text) {
  return el('div', 'state-block state-block--loading', text || '加载中…');
}

function emptyBlock(title, hint) {
  const box = el('div', 'state-block');
  box.appendChild(el('div', 'state-block__title', title || '暂无数据'));
  if (hint) box.appendChild(el('div', 'state-block__hint', hint));
  return box;
}

function errorBlock(message, onRetry) {
  const box = el('div', 'error-block');
  box.appendChild(el('span', 'error-block__msg', textOr(message, '加载失败。')));
  if (typeof onRetry === 'function') {
    box.appendChild(button('重试', { variant: 'ghost', size: 'sm', onClick: onRetry }));
  }
  return box;
}

function defList(items) {
  const dl = el('dl', 'def-list');
  items.forEach(function (item) {
    dl.appendChild(el('dt', 'def-list__k', item.label));
    const dd = el('dd', 'def-list__v');
    if (item.mono) dd.classList.add('mono');
    dd.textContent = textOr(item.value);
    if (item.title) dd.title = String(item.title);
    dl.appendChild(dd);
  });
  return dl;
}

/* 审计表：总览、审计页、节点详情共用 */
function createAuditTable() {
  return createTable([
    { label: '时间' },
    { label: '节点' },
    { label: '类型' },
    { label: '路径' },
    { label: '主体' },
    { label: '详情' },
    { label: '结果' },
  ]);
}

function auditRow(record) {
  const rec = record && typeof record === 'object' ? record : {};
  const tr = el('tr');
  tr.appendChild(cell(fmtTime(rec.ts), 'mono cell-nowrap'));
  tr.appendChild(cell(textOr(rec.agent), 'mono cell-ellipsis', textOr(rec.agent)));

  const kindRaw = textOr(rec.kind);
  const kindTd = el('td');
  const kindSpan = el('span', 'mono', kindRaw);
  if (AUDIT_KIND_LABELS[kindRaw]) kindSpan.title = AUDIT_KIND_LABELS[kindRaw];
  kindTd.appendChild(kindSpan);
  tr.appendChild(kindTd);

  tr.appendChild(cell(textOr(rec.path), 'mono cell-ellipsis', textOr(rec.path)));
  tr.appendChild(cell(textOr(rec.subject), 'cell-ellipsis', textOr(rec.subject)));
  const detailText = typeof rec.detail === 'string' ? rec.detail : '';
  tr.appendChild(cell(detailText || '—', 'detail-cell cell-ellipsis', detailText));

  const decisionRaw = typeof rec.decision === 'string' ? rec.decision.trim() : '';
  const decisionMeta = DECISION_META[decisionRaw];
  const decisionTd = el('td');
  if (decisionMeta) {
    decisionTd.appendChild(badge(decisionMeta.label, decisionMeta.tone, decisionRaw));
  } else {
    decisionTd.appendChild(el('span', 'muted', decisionRaw || '—'));
  }
  tr.appendChild(decisionTd);
  return tr;
}

/* --------------------------------------------------------------------------
 * 抽屉 / 确认弹窗
 * ------------------------------------------------------------------------ */

function closeDrawerOnly() {
  if (state.drawer) {
    const drawer = state.drawer;
    state.drawer = null;
    drawer.closeProgrammatic();
  }
}

function closeAllOverlays() {
  closeDrawerOnly();
  if (state.modal) {
    const modal = state.modal;
    state.modal = null;
    modal.finish(false);
  }
}

function createDrawer(options) {
  const opts = options || {};
  closeDrawerOnly();

  const overlay = el('div', 'drawer-overlay');
  const drawer = el('aside', 'drawer');
  drawer.setAttribute('role', 'dialog');
  drawer.setAttribute('aria-modal', 'true');

  const head = el('header', 'drawer__head');
  const heading = el('div', 'drawer__heading');
  const titleEl = el('h2', 'drawer__title', opts.title || '详情');
  const subEl = el('p', 'drawer__subtitle mono', opts.subtitle || '');
  heading.append(titleEl, subEl);
  const closeBtn = el('button', 'drawer__close', '×');
  closeBtn.type = 'button';
  closeBtn.setAttribute('aria-label', '关闭详情');
  head.append(heading, closeBtn);

  const body = el('div', 'drawer__body');
  drawer.append(head, body);
  document.body.append(overlay, drawer);
  // 下一帧再加过渡类，保证进场动画生效
  requestAnimationFrame(function () {
    drawer.classList.add('drawer--open');
    overlay.classList.add('drawer-overlay--open');
  });

  let closed = false;
  const handle = {
    body: body,
    isOpen: function () {
      return !closed;
    },
    setTitle: function (nextTitle, nextSubtitle) {
      titleEl.textContent = textOr(nextTitle, '详情');
      subEl.textContent = nextSubtitle === undefined || nextSubtitle === null ? '' : String(nextSubtitle);
    },
    closeProgrammatic: function () {
      close(false);
    },
  };

  function onKey(event) {
    if (event.key !== 'Escape') return;
    // 确认弹窗打开时 Esc 归弹窗处理，避免把下层抽屉一并关掉
    if (state.modal) return;
    event.preventDefault();
    close(true);
  }

  function close(fromUser) {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKey);
    drawer.remove();
    overlay.remove();
    if (state.drawer === handle) state.drawer = null;
    if (fromUser && typeof opts.onUserClose === 'function') opts.onUserClose();
  }

  closeBtn.addEventListener('click', function () {
    close(true);
  });
  overlay.addEventListener('click', function () {
    close(true);
  });
  document.addEventListener('keydown', onKey);

  state.drawer = handle;
  return handle;
}

function confirmDialog(options) {
  const opts = options || {};
  return new Promise(function (resolve) {
    if (state.modal) {
      const previous = state.modal;
      state.modal = null;
      previous.finish(false);
    }
    const overlay = el('div', 'modal-overlay');
    const modal = el('div', 'modal');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');

    const title = el('h2', 'modal__title', opts.title || '请确认');
    const message = el('p', 'modal__msg', opts.message || '');
    modal.append(title, message);
    if (opts.detail) modal.appendChild(el('p', 'modal__detail', opts.detail));

    const actions = el('div', 'modal__actions');
    const cancelBtn = button(opts.cancelText || '取消', {
      variant: 'ghost',
      onClick: function () {
        finish(false);
      },
    });
    const okBtn = button(opts.confirmText || '确认', {
      variant: opts.danger ? 'danger-solid' : 'primary',
      onClick: function () {
        finish(true);
      },
    });
    actions.append(cancelBtn, okBtn);
    modal.appendChild(actions);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    okBtn.focus();

    let done = false;
    function finish(result) {
      if (done) return;
      done = true;
      document.removeEventListener('keydown', onKey);
      overlay.remove();
      if (state.modal && state.modal.finish === finish) state.modal = null;
      resolve(result);
    }
    function onKey(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        finish(false);
      }
    }
    document.addEventListener('keydown', onKey);
    state.modal = { finish: finish };
  });
}

// 展示一次性的卸载挑战码（票据），带复制按钮。
function showTicketDialog(title, code, detail) {
  return new Promise(function (resolve) {
    if (state.modal) {
      const previous = state.modal;
      state.modal = null;
      previous.finish(false);
    }
    const overlay = el('div', 'modal-overlay');
    const modal = el('div', 'modal');
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.appendChild(el('h2', 'modal__title', title || '挑战码'));
    if (detail) modal.appendChild(el('p', 'modal__detail', detail));
    const box = el('textarea', 'mono');
    box.readOnly = true;
    box.rows = 4;
    box.style.width = '100%';
    box.value = code || '';
    modal.appendChild(box);
    const actions = el('div', 'modal__actions');
    const copyBtn = button('复制挑战码', {
      variant: 'primary',
      onClick: function () {
        box.select();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(box.value).then(function () {
            toast('挑战码已复制。', 'success');
          }, function () {});
        }
      },
    });
    const closeBtn = button('关闭', {
      variant: 'ghost',
      onClick: function () {
        finish();
      },
    });
    actions.append(copyBtn, closeBtn);
    modal.appendChild(actions);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    box.focus();
    let done = false;
    function finish() {
      if (done) return;
      done = true;
      document.removeEventListener('keydown', onKey);
      overlay.remove();
      if (state.modal && state.modal.finish === finish) state.modal = null;
      resolve(true);
    }
    function onKey(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        finish();
      }
    }
    document.addEventListener('keydown', onKey);
    state.modal = { finish: finish };
  });
}

/* --------------------------------------------------------------------------
 * 主题：自动 / 白天 / 夜间
 * ------------------------------------------------------------------------ */

const THEME_KEY = 'tg-theme';

function themePreference() {
  try {
    const v = localStorage.getItem(THEME_KEY);
    if (v === 'light' || v === 'dark' || v === 'auto') return v;
  } catch (err) { /* private mode */ }
  return 'auto';
}

function resolvedTheme(pref) {
  if (pref === 'light' || pref === 'dark') return pref;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function applyTheme(pref) {
  document.documentElement.setAttribute('data-theme', resolvedTheme(pref));
  try { localStorage.setItem(THEME_KEY, pref); } catch (err) { /* ignore */ }
}

function updateThemeButton(btn) {
  if (!btn) return;
  const pref = themePreference();
  btn.textContent = pref === 'light' ? '主题：白天' : pref === 'dark' ? '主题：夜间' : '主题：自动';
}

function cycleTheme(btn) {
  const order = ['auto', 'light', 'dark'];
  const next = order[(order.indexOf(themePreference()) + 1) % order.length];
  applyTheme(next);
  updateThemeButton(btn);
  toast('主题：' + (next === 'auto' ? '跟随系统' : next === 'light' ? '白天' : '夜间'), 'success');
}

function initTheme() {
  applyTheme(themePreference());
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const onChange = function () {
      if (themePreference() === 'auto') applyTheme('auto');
    };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }
}

/* --------------------------------------------------------------------------
 * 修改管理员密码
 * ------------------------------------------------------------------------ */

function openPasswordDialog() {
  if (state.modal) {
    const previous = state.modal;
    state.modal = null;
    previous.finish(false);
  }
  const overlay = el('div', 'modal-overlay');
  const modal = el('div', 'modal');
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.appendChild(el('h2', 'modal__title', '修改管理员密码'));
  modal.appendChild(el('p', 'modal__detail', '需要验证当前密码；新密码至少 8 位。'));

  function field(labelText, id, autocomplete) {
    const label = el('label', 'field');
    label.appendChild(el('span', '', labelText));
    const input = el('input', '');
    input.type = 'password';
    input.id = id;
    input.autocomplete = autocomplete || 'off';
    label.appendChild(input);
    modal.appendChild(label);
    return input;
  }

  const current = field('当前密码', 'pw-current', 'current-password');
  const next = field('新密码', 'pw-new', 'new-password');
  const confirm = field('确认新密码', 'pw-confirm', 'new-password');

  const actions = el('div', 'modal__actions');
  const cancelBtn = button('取消', {
    variant: 'ghost',
    onClick: function () { finish(false); },
  });
  const saveBtn = button('保存', {
    variant: 'primary',
    onClick: async function () {
      if (next.value.length < 8) {
        toast('新密码至少 8 位。', 'error');
        return;
      }
      if (next.value !== confirm.value) {
        toast('两次输入的新密码不一致。', 'error');
        return;
      }
      saveBtn.disabled = true;
      try {
        await api('POST', '/auth/password', {
          body: { current_password: current.value, new_password: next.value },
        });
        toast('管理员密码已修改。', 'success');
        finish(true);
      } catch (err) {
        saveBtn.disabled = false;
        if (isAborted(err) || err.handled) return;
        toast(err.message || '修改密码失败。', 'error');
      }
    },
  });
  actions.append(cancelBtn, saveBtn);
  modal.appendChild(actions);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  current.focus();

  let done = false;
  function finish() {
    if (done) return;
    done = true;
    document.removeEventListener('keydown', onKey);
    overlay.remove();
    if (state.modal && state.modal.finish === finish) state.modal = null;
  }
  function onKey(event) {
    if (event.key === 'Escape') {
      event.preventDefault();
      finish();
    }
  }
  document.addEventListener('keydown', onKey);
  state.modal = { finish: finish };
}

/* --------------------------------------------------------------------------
 * 登录 / 会话
 * ------------------------------------------------------------------------ */

function renderLogin() {
  state.currentView = null;
  document.title = '登录 · TamperGuard 管理端';
  const app = document.getElementById('app');
  if (!app) return;
  app.innerHTML = LOGIN_HTML; // 静态骨架

  const bootNote = document.getElementById('login-boot-note');
  if (bootNote && state.bootError) {
    bootNote.classList.remove('hidden');
    bootNote.textContent = '无法连接后端服务：' + state.bootError + '（页面可离线预览，登录请求会失败）';
  }

  const form = document.getElementById('login-form');
  const userInput = document.getElementById('login-username');
  const passInput = document.getElementById('login-password');
  const errorBox = document.getElementById('login-error');
  const submitBtn = document.getElementById('login-submit');
  let busy = false;

  form.addEventListener('submit', async function (event) {
    event.preventDefault();
    if (busy) return;
    errorBox.textContent = '';
    errorBox.classList.add('hidden');

    const username = userInput.value.trim();
    const password = passInput.value;
    if (!username || !password) {
      errorBox.textContent = !username ? '请输入用户名。' : '请输入密码。';
      errorBox.classList.remove('hidden');
      return;
    }

    busy = true;
    submitBtn.disabled = true;
    submitBtn.textContent = '登录中…';
    try {
      const user = await api('POST', '/auth/login', {
        body: { username: username, password: password },
        allow401: true,
      });
      state.me = user && typeof user === 'object' ? user : { username: username };
      state.bootError = null;
      state.authNotified = false;
      toast('登录成功。', 'success');
      const target = state.pendingHash || '#/overview';
      state.pendingHash = null;
      if (location.hash === target) {
        handleRoute();
      } else {
        location.hash = target;
      }
    } catch (err) {
      if (isAborted(err)) return;
      const message = err.status === 401
        ? '用户名或密码错误，或该账号无权登录管理端。'
        : (err.message || '登录失败，请稍后重试。');
      errorBox.textContent = message;
      errorBox.classList.remove('hidden');
      if (!err.handled) toast(message, 'error');
      passInput.value = '';
      passInput.focus();
    } finally {
      busy = false;
      submitBtn.disabled = false;
      submitBtn.textContent = '登录';
    }
  });
}

async function detectSession() {
  try {
    const me = await api('GET', '/auth/me', { allow401: true });
    state.me = me && typeof me === 'object' ? me : null;
    state.bootError = null;
  } catch (err) {
    state.me = null;
    if (isAborted(err)) return;
    // 401 表示尚未登录，属于正常初始状态，不提示离线
    state.bootError = err.status === 401 ? null : (err.message || '无法连接服务端。');
  }
}

async function handleLogout(event) {
  const btn = event && event.currentTarget ? event.currentTarget : null;
  if (btn) {
    btn.disabled = true;
    btn.textContent = '正在退出…';
  }
  try {
    await api('POST', '/auth/logout');
  } catch (err) {
    if (!isAborted(err) && !err.handled) toast(err.message || '退出登录请求失败。', 'error');
  } finally {
    state.me = null;
    state.authNotified = false;
    state.pendingHash = null;
    if (btn) {
      btn.disabled = false;
      btn.textContent = '退出登录';
    }
    closeAllOverlays();
    toast('已退出登录。', 'success');
    if (location.hash === '#/login') renderLogin();
    else setHash('#/login');
  }
}

/* --------------------------------------------------------------------------
 * 管理端骨架
 * ------------------------------------------------------------------------ */

function buildSidebar(nav) {
  NAV_ITEMS.forEach(function (item) {
    const link = el('a', 'nav__item', item.label);
    link.href = item.hash;
    link.dataset.key = item.key;
    nav.appendChild(link);
  });
}

function renderShell(route) {
  const app = document.getElementById('app');
  if (!app) return;
  if (!app.querySelector('.layout')) {
    app.innerHTML = SHELL_HTML; // 静态骨架
    buildSidebar(app.querySelector('#nav'));
    const logoutBtn = app.querySelector('#logout-btn');
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
    const themeBtn = app.querySelector('#theme-btn');
    if (themeBtn) {
      updateThemeButton(themeBtn);
      themeBtn.addEventListener('click', function () { cycleTheme(themeBtn); });
    }
    const passwordBtn = app.querySelector('#password-btn');
    if (passwordBtn) passwordBtn.addEventListener('click', openPasswordDialog);
  }

  const activeKey = NAV_ACTIVE_MAP[route.name] || '';
  app.querySelectorAll('.nav__item').forEach(function (item) {
    const active = item.dataset.key === activeKey;
    item.classList.toggle('nav__item--active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });

  const titleEl = app.querySelector('#page-title');
  if (titleEl) titleEl.textContent = ROUTE_TITLES[route.name] || 'TamperGuard';

  const nameEl = app.querySelector('#user-name');
  if (nameEl) {
    nameEl.textContent = state.me && state.me.username ? String(state.me.username) : '当前用户';
  }
  const roleEl = app.querySelector('#user-role');
  if (roleEl) {
    const roleRaw = state.me && state.me.role ? String(state.me.role) : '';
    roleEl.textContent = roleRaw === 'admin' ? '管理员' : roleRaw;
    roleEl.classList.toggle('hidden', !roleEl.textContent);
  }
}

/* --------------------------------------------------------------------------
 * 路由
 * ------------------------------------------------------------------------ */

function parseRoute() {
  let raw = location.hash || '';
  if (raw.charAt(0) === '#') raw = raw.slice(1);
  const path = raw.split('?')[0];
  const segments = path.split('/').filter(Boolean).map(function (segment) {
    try {
      return decodeURIComponent(segment);
    } catch (err) {
      return segment;
    }
  });

  if (segments.length === 0) return { name: 'overview' };
  switch (segments[0]) {
    case 'login':
      return { name: 'login' };
    case 'overview':
      return { name: 'overview' };
    case 'nodes':
      if (segments.length === 1) return { name: 'nodes' };
      if (segments.length === 2) return { name: 'node-detail', id: segments[1] };
      return { name: 'not-found' };
    case 'policies':
      if (segments.length === 1) return { name: 'policies' };
      if (segments.length === 2 && segments[1] === 'new') return { name: 'policy-new' };
      if (segments.length === 3 && segments[2] === 'edit') return { name: 'policy-edit', id: segments[1] };
      return { name: 'not-found' };
    case 'publish':
      return { name: 'publish' };
    case 'audit':
      return { name: 'audit' };
    case 'revocations':
      return { name: 'revocations' };
    default:
      return { name: 'not-found' };
  }
}

function createView(route) {
  switch (route.name) {
    case 'overview':
      return overviewView();
    case 'nodes':
      return nodesView({});
    case 'node-detail':
      return nodesView({ id: route.id });
    case 'policies':
      return policiesListView();
    case 'policy-new':
      return policyEditorView({ mode: 'create' });
    case 'policy-edit':
      return policyEditorView({ mode: 'edit', id: route.id });
    case 'publish':
      return publishView();
    case 'audit':
      return auditView();
    case 'revocations':
      return revocationsView();
    default:
      return notFoundView();
  }
}

function renderViewError(host, err) {
  clear(host);
  const panelRef = buildPanel('页面加载失败', { bodyClass: 'panel__body' });
  panelRef.body.appendChild(errorBlock(err && err.message ? err.message : '页面加载失败。', function () {
    handleRoute();
  }));
  host.appendChild(panelRef.panel);
}

async function handleRoute() {
  const previous = state.currentView;
  state.currentView = null;
  if (previous && typeof previous.destroy === 'function') {
    try {
      previous.destroy();
    } catch (err) {
      /* 视图清理失败不影响后续导航 */
    }
  }
  closeAllOverlays();

  const route = parseRoute();

  if (route.name === 'login') {
    if (state.me) {
      state.pendingHash = null;
      setHash('#/overview', true);
      return;
    }
    renderLogin();
    return;
  }

  if (!state.me) {
    if (location.hash && location.hash !== '#/login') state.pendingHash = location.hash;
    if (location.hash !== '#/login') setHash('#/login');
    else renderLogin();
    return;
  }

  state.authNotified = false;
  renderShell(route);
  document.title = (ROUTE_TITLES[route.name] || 'TamperGuard') + ' · TamperGuard 管理端';

  const host = document.getElementById('view');
  if (!host) return;
  clear(host);

  let view = null;
  try {
    view = createView(route);
    state.currentView = view;
    await view.mount(host);
  } catch (err) {
    if (isAborted(err) || (view && state.currentView !== view)) return;
    renderViewError(host, err);
  }
}

function onRouteError(err) {
  if (isAborted(err)) return;
  toast(err && err.message ? err.message : '页面切换失败。', 'error');
}

/* --------------------------------------------------------------------------
 * 总览
 * ------------------------------------------------------------------------ */

function renderAlerts(container, nodesResult, overviewResult) {
  clear(container);
  const rows = [];

  if (nodesResult.status === 'fulfilled') {
    if (Array.isArray(nodesResult.value)) {
      nodesResult.value.forEach(function (node) {
        if (node && node.degraded && !node.degraded_approved) {
          rows.push(el('div', 'alert-row alert-row--danger'));
          const row = rows[rows.length - 1];
          row.appendChild(el('span', 'alert-row__mark'));
          const textBox = el('div', 'alert-row__text');
          textBox.appendChild(el('div', 'alert-row__title', '节点 ' + textOr(node.hostname, node.id) + ' 处于降级防护，尚未审批'));
          textBox.appendChild(el('div', 'alert-row__desc', 'enforcer：' + enforcerLabel(node.enforcer) + ' · 最后心跳：' + fmtTime(node.last_seen)));
          row.appendChild(textBox);
          const action = button('前往处理', { size: 'sm' });
          action.addEventListener('click', function () {
            location.hash = '#/nodes/' + encodeURIComponent(node.id);
          });
          row.appendChild(action);
        }
      });
    } else {
      const row = el('div', 'alert-row alert-row--warn');
      row.appendChild(el('span', 'alert-row__mark'));
      const textBox = el('div', 'alert-row__text');
      textBox.appendChild(el('div', 'alert-row__title', '节点接口返回格式异常，告警信息可能不完整。'));
      textBox.appendChild(el('div', 'alert-row__desc', '请点击右上角刷新重试。'));
      row.appendChild(textBox);
      rows.push(row);
    }
  } else if (!isAborted(nodesResult.reason)) {
    const row = el('div', 'alert-row alert-row--warn');
    row.appendChild(el('span', 'alert-row__mark'));
    const textBox = el('div', 'alert-row__text');
    textBox.appendChild(el('div', 'alert-row__title', '节点列表加载失败，无法确认降级未审批节点。'));
    textBox.appendChild(el('div', 'alert-row__desc', nodesResult.reason && nodesResult.reason.message ? nodesResult.reason.message : '请稍后重试。'));
    row.appendChild(textBox);
    rows.push(row);
  }

  if (overviewResult.status === 'fulfilled' && overviewResult.value && Number(overviewResult.value.chain_alerts) > 0) {
    const row = el('div', 'alert-row alert-row--danger');
    row.appendChild(el('span', 'alert-row__mark'));
    const textBox = el('div', 'alert-row__text');
    textBox.appendChild(el('div', 'alert-row__title', '审计链告警 ' + metricNumber(overviewResult.value.chain_alerts) + ' 条'));
    textBox.appendChild(el('div', 'alert-row__desc', '存在序号缺口或哈希分叉，需要尽快核对审计记录。'));
    row.appendChild(textBox);
    const action = button('查看审计', { size: 'sm' });
    action.addEventListener('click', function () {
      location.hash = '#/audit';
    });
    row.appendChild(action);
    rows.push(row);
  }

  if (rows.length === 0) {
    const row = el('div', 'alert-row alert-row--ok');
    row.appendChild(el('span', 'alert-row__mark'));
    const textBox = el('div', 'alert-row__text');
    textBox.appendChild(el('div', 'alert-row__title', '当前没有需要处理的告警。'));
    textBox.appendChild(el('div', 'alert-row__desc', '节点防护正常，审计链无异常。'));
    row.appendChild(textBox);
    rows.push(row);
  }

  rows.forEach(function (row) {
    container.appendChild(row);
  });
}

function metricCard(card) {
  const box = el('div', 'metric' + (card.tone ? ' metric--' + card.tone : ''));
  box.appendChild(el('span', 'metric__label', card.label));
  box.appendChild(el('span', 'metric__value', card.value));
  if (card.hint) box.appendChild(el('span', 'metric__hint', card.hint));
  return box;
}

function renderOverviewMetrics(container, overviewResult, retry) {
  clear(container);
  if (overviewResult.status !== 'fulfilled' || !overviewResult.value || typeof overviewResult.value !== 'object') {
    const wrap = el('div', 'span-all');
    const message = overviewResult.status === 'rejected'
      ? (overviewResult.reason && overviewResult.reason.message ? overviewResult.reason.message : '总览数据加载失败。')
      : '总览接口返回格式异常。';
    wrap.appendChild(errorBlock(message, retry));
    container.appendChild(wrap);
    return;
  }
  const data = overviewResult.value;
  const cards = [
    { label: '节点总数', value: metricNumber(data.nodes_total), hint: '已纳管节点' },
    { label: '在线节点', value: metricNumber(data.nodes_online), hint: '心跳正常' },
    {
      label: '降级节点',
      value: metricNumber(data.nodes_degraded),
      hint: '防护能力受限',
      tone: Number(data.nodes_degraded) > 0 ? 'warn' : '',
    },
    { label: '24 小时拦截', value: metricNumber(data.blocked_24h), hint: 'write.blocked 事件' },
    { label: '活跃令牌', value: metricNumber(data.tokens_active), hint: '未过期的释放令牌' },
    {
      label: '审计链告警',
      value: metricNumber(data.chain_alerts),
      hint: '序号缺口 / 哈希分叉',
      tone: Number(data.chain_alerts) > 0 ? 'danger' : '',
    },
  ];
  cards.forEach(function (card) {
    container.appendChild(metricCard(card));
  });
}

function renderOverviewAudit(container, auditResult, retry) {
  clear(container);
  if (auditResult.status === 'rejected') {
    if (isAborted(auditResult.reason)) return;
    container.appendChild(errorBlock(
      auditResult.reason && auditResult.reason.message ? auditResult.reason.message : '审计事件加载失败。',
      retry
    ));
    return;
  }
  if (!Array.isArray(auditResult.value)) {
    container.appendChild(errorBlock('审计接口返回格式异常（期望数组）。', retry));
    return;
  }
  if (auditResult.value.length === 0) {
    container.appendChild(emptyBlock('暂无审计事件', '节点上报事件后会显示在这里。'));
    return;
  }
  const built = createAuditTable();
  auditResult.value.forEach(function (record) {
    built.tbody.appendChild(auditRow(record));
  });
  const wrap = el('div', 'table-wrap');
  wrap.appendChild(built.table);
  container.appendChild(wrap);
}

function overviewView() {
  const ac = new AbortController();
  let destroyed = false;
  let loading = false;
  let refs = null;

  async function loadAll() {
    if (loading || destroyed) return;
    loading = true;
    if (refs) {
      clear(refs.alerts);
      refs.alerts.appendChild(loadingBlock('正在加载告警…'));
      clear(refs.metrics);
      const metricsLoading = el('div', 'span-all');
      metricsLoading.appendChild(loadingBlock('正在加载指标…'));
      refs.metrics.appendChild(metricsLoading);
      clear(refs.audit);
      refs.audit.appendChild(loadingBlock('正在加载审计事件…'));
    }
    const results = await Promise.allSettled([
      api('GET', '/overview', { signal: ac.signal }),
      api('GET', '/nodes', { signal: ac.signal }),
      api('GET', '/audit', { query: { limit: 20 }, signal: ac.signal }),
    ]);
    loading = false;
    if (destroyed || !refs) return;
    renderAlerts(refs.alerts, results[1], results[0]);
    renderOverviewMetrics(refs.metrics, results[0], function () {
      loadAll();
    });
    renderOverviewAudit(refs.audit, results[2], function () {
      loadAll();
    });
  }

  return {
    async mount(host) {
      host.appendChild(buildPageHead({
        title: '总览',
        desc: '防护状态、待处理告警与最近审计事件',
        actions: [button('刷新', { onClick: function () { loadAll(); } })],
      }));
      const alertsPanel = buildPanel('需要处理的告警', { bodyClass: 'panel__body panel__body--flush' });
      const metricsGrid = el('div', 'metrics');
      const auditPanel = buildPanel('最近审计事件', {
        bodyClass: 'panel__body panel__body--flush',
        link: { label: '查看全部', href: '#/audit' },
      });
      refs = { alerts: alertsPanel.body, metrics: metricsGrid, audit: auditPanel.body };
      host.append(alertsPanel.panel, metricsGrid, auditPanel.panel);
      await loadAll();
    },
    destroy() {
      destroyed = true;
      ac.abort();
    },
  };
}

/* --------------------------------------------------------------------------
 * 节点
 * ------------------------------------------------------------------------ */

function nodesView(options) {
  const opts = options || {};
  const ac = new AbortController();
  let destroyed = false;
  let nodes = null;
  let loading = false;
  let listRefs = null;
  let filterValue = 'all';
  let uninstallRequests = [];

  async function loadNodes(loadOptions) {
    const settings = loadOptions || {};
    if (loading || destroyed) return;
    loading = true;
    if (!settings.silent && listRefs) {
      clear(listRefs.body);
      listRefs.body.appendChild(loadingBlock('正在加载节点…'));
    }
    try {
      const results = await Promise.all([
        api('GET', '/nodes', { signal: ac.signal }),
        api('GET', '/uninstall-requests?status=pending', { signal: ac.signal }).catch(function () { return []; }),
      ]);
      if (destroyed) return;
      const data = results[0];
      if (!Array.isArray(data)) {
        renderListError('节点接口返回格式异常（期望数组）。');
        return;
      }
      nodes = data;
      uninstallRequests = Array.isArray(results[1]) ? results[1] : [];
      renderList();
    } catch (err) {
      if (isAborted(err) || destroyed) return;
      renderListError(err.message || '节点列表加载失败。');
    } finally {
      loading = false;
    }
  }

  function renderListError(message) {
    if (!listRefs) return;
    clear(listRefs.body);
    listRefs.body.appendChild(errorBlock(message, function () {
      loadNodes();
    }));
    if (listRefs.count) listRefs.count.textContent = '';
  }

  function visibleNodes() {
    const list = Array.isArray(nodes) ? nodes : [];
    if (filterValue === 'degraded') {
      return list.filter(function (node) {
        return node && node.degraded && !node.degraded_approved;
      });
    }
    if (filterValue === 'online') {
      return list.filter(function (node) { return node && node.status === 'online'; });
    }
    if (filterValue === 'offline') {
      return list.filter(function (node) { return node && node.status === 'offline'; });
    }
    if (filterValue === 'uninstalled') {
      return list.filter(function (node) {
        return node && (node.status === 'uninstalled' || node.status === 'uninstalling');
      });
    }
    return list;
  }

  function nodeRow(node) {
    const tr = el('tr', 'row-click');
    tr.tabIndex = 0;

    function openDetail() {
      location.hash = '#/nodes/' + encodeURIComponent(node.id);
    }

    const hostTd = el('td', 'cell-host');
    hostTd.appendChild(el('span', 'cell-host__name', textOr(node.hostname, node.id)));
    hostTd.appendChild(el('span', 'cell-host__id mono', textOr(node.id)));
    tr.appendChild(hostTd);

    const statusMeta = NODE_STATUS_META[node.status] || { label: textOr(node.status), tone: 'muted' };
    tr.appendChild(cellNode(badge(statusMeta.label, statusMeta.tone, textOr(node.status))));

    const enforcerTd = el('td');
    const enforcerSpan = el('span', node.enforcer === 'observe' ? 'text-warn' : '', enforcerLabel(node.enforcer));
    enforcerTd.appendChild(enforcerSpan);
    if (node.enforcer === 'observe') enforcerTd.appendChild(el('span', 'cell-sub', '仅观察，不拦截'));
    tr.appendChild(enforcerTd);

    const hasPolicyVersion = node.policy_version !== undefined && node.policy_version !== null && Number(node.policy_version) > 0;
    tr.appendChild(cell(hasPolicyVersion ? 'v' + node.policy_version : '—', 'mono'));

    const seenTd = el('td');
    seenTd.appendChild(el('span', 'cell-nowrap', fmtTime(node.last_seen)));
    const ago = fmtAgo(node.last_seen);
    if (ago) seenTd.appendChild(el('span', 'cell-sub', ago));
    tr.appendChild(seenTd);

    const deg = degradedInfo(node);
    tr.appendChild(cellNode(badge(deg.label, deg.tone)));

    const actionTd = el('td');
    if (node.role === 'protect' && node.status !== 'uninstalled' && node.status !== 'uninstalling') {
      actionTd.appendChild(button('卸载', {
        variant: 'danger',
        onClick: function (event) {
          if (event) event.stopPropagation();
          requestNodeUninstall(node);
        },
      }));
    }
    if (node.status === 'offline' || node.status === 'uninstalled') {
      actionTd.appendChild(button('删除', {
        variant: 'ghost',
        onClick: function (event) {
          if (event) event.stopPropagation();
          purgeNode(node);
        },
      }));
    }
    if (!actionTd.childNodes.length) {
      actionTd.appendChild(el('span', 'muted', '—'));
    }
    tr.appendChild(actionTd);

    tr.addEventListener('click', openDetail);
    tr.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        openDetail();
      }
    });
    return tr;
  }


  async function linuxOneCommand(role) {
    const isPublish = role === 'publish';
    try {
      const res = await api('POST', '/bootstrap-tokens', { body: { role: role }, signal: ac.signal });
      const url = location.origin + '/api/v1/install.sh?role=' + role + '&token=' + encodeURIComponent(res.token);
      const cmd = 'curl -fsSLk "' + url + '" | sudo bash';
      showTicketDialog(isPublish ? 'Linux 发布端一键注册' : 'Linux 被防护端一键注册', res.token,
        '在目标主机上执行这一条命令：\n\n' + cmd + '\n\n令牌一次性有效，请在 10 分钟内执行。');
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '生成一键安装命令失败。', 'error');
    }
  }

  async function issueAgentToken(role) {
    const isPublish = role === 'publish';
    const title = isPublish ? '发布端安装' : '被防护端安装';
    try {
      const res = await api('POST', '/bootstrap-tokens', { body: { role: role }, signal: ac.signal });
      const server = location.origin;
      const caURL = server + '/api/v1/downloads/agent?file=ca.crt';
      const linuxDownload = server + '/api/v1/downloads/agent?role=' + role + '&os=linux&arch=amd64';
      const windowsDownload = server + '/api/v1/downloads/agent?role=' + role + '&os=windows&arch=amd64';
      const linuxEnroll = isPublish
        ? 'sudo ./tg-agent enroll --server ' + server + ' --bootstrap ' + res.token +
          ' --ca ca.crt --role publish --state-dir /var/lib/tamperguard-publish\n' +
          'sudo tg-publish run --state-dir /var/lib/tamperguard-publish'
        : 'sudo ./tg-agent enroll --server ' + server + ' --bootstrap ' + res.token +
          ' --ca ca.crt --role protect --state-dir /var/lib/tamperguard-agent --publisher-uids 0\n' +
          'sudo systemctl enable --now tamperguard-agent';
      const windowsEnroll = isPublish
        ? '.\\tg-agent.exe enroll --server ' + server + ' --bootstrap ' + res.token +
          ' --ca ca.crt --role publish --state-dir C:\\ProgramData\\TamperGuard-publish\n' +
          '.\\tg-publish.exe run --state-dir C:\\ProgramData\\TamperGuard-publish'
        : '# 管理员 PowerShell\n.\\tg-agent.exe enroll --server ' + server + ' --bootstrap ' + res.token +
          ' --ca ca.crt --role protect --state-dir C:\\ProgramData\\TamperGuard --publisher-sids "DOMAIN\\svc-publish"\n' +
          '.\\install-service.ps1';
      const detail = '令牌仅可使用一次。\n\n' +
        'Linux 下载：' + linuxDownload + '\n' +
        'Linux 命令：\n' + linuxEnroll + '\n\n' +
        'Windows 下载：' + windowsDownload + '\n' +
        'Windows 命令：\n' + windowsEnroll + '\n\n' +
        'CA 证书下载：' + caURL + '\n把 ca.crt 与二进制放在同一目录，或用 --ca 指向实际路径。';
      showTicketDialog(title, res.token, detail);
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '生成安装令牌失败。', 'error');
    }
  }

  function renderAgentInstallPanel(host) {
    const panel = buildPanel('Agent 下载与安装', { bodyClass: 'panel__body' });
    const grid = el('div', 'install-grid');

    function card(role, title, desc) {
      const box = el('div', 'install-card');
      box.appendChild(el('h3', 'install-card__title', title));
      box.appendChild(el('p', 'install-card__desc', desc));
      const actions = el('div', 'row-actions');
      const win = el('a', 'btn btn--sm btn--primary', 'Windows 一键安装包');
      win.href = '/api/v1/install/package?role=' + role;
      win.setAttribute('download', '');
      actions.appendChild(win);

      actions.appendChild(button('Linux 一键安装命令', {
        variant: 'primary',
        size: 'sm',
        onClick: function () { linuxOneCommand(role); },
      }));

      const linux = el('a', 'btn btn--sm', '下载 Linux 版');
      linux.href = '/api/v1/downloads/agent?role=' + role + '&os=linux&arch=amd64';
      linux.setAttribute('download', '');
      actions.appendChild(linux);

      const ca = el('a', 'btn btn--sm', '下载 CA 证书');
      ca.href = '/api/v1/downloads/agent?file=ca.crt';
      ca.setAttribute('download', '');
      actions.appendChild(ca);
      box.appendChild(actions);
      return box;
    }

    grid.appendChild(card('protect', '被防护端 Agent（Linux / Windows）',
      '安装到被保护主机，执行文件层阻断与自愈。下载后按提示注册为服务。'));
    grid.appendChild(card('publish', '发布端 Agent',
      '安装到发布/构建主机，执行同步任务。支持本机写入与跨机 pull 两种方式。'));
    panel.body.appendChild(grid);
    host.appendChild(panel.panel);
  }

  function renderList() {
    if (!listRefs) return;
    const list = visibleNodes();
    const total = Array.isArray(nodes) ? nodes.length : 0;
    listRefs.count.textContent = list.length + ' / ' + total + ' 个节点';
    clear(listRefs.body);
    if (total === 0) {
      listRefs.body.appendChild(emptyBlock('尚未纳管任何节点', '节点执行 agent 注册后，这里会显示其状态。'));
      return;
    }
    if (list.length === 0) {
      listRefs.body.appendChild(emptyBlock('没有符合筛选条件的节点', '调整筛选条件后重试。'));
      return;
    }
    const built = createTable([
      { label: '主机名' },
      { label: '状态' },
      { label: '防护模式' },
      { label: '策略版本' },
      { label: '最后心跳' },
      { label: '降级状态' },
      { label: '操作' },
    ]);
    list.forEach(function (node) {
      built.tbody.appendChild(nodeRow(node));
    });
    const wrap = el('div', 'table-wrap');
    wrap.appendChild(built.table);
    listRefs.body.appendChild(wrap);
    renderUninstallPanel(listRefs.body);
  }

  function renderUninstallPanel(host) {
    const section = el('section', 'card');
    const head = el('div', 'card__head');
    head.appendChild(el('h2', 'card__title', '卸载审批'));
    head.appendChild(el('span', 'muted', uninstallRequests.length + ' 个待审批请求'));
    section.appendChild(head);
    if (!uninstallRequests.length) {
      section.appendChild(el('p', 'muted', '当前没有客户端发起的卸载请求。管理员如需卸载某节点，可在节点详情中点击「下发卸载」。'));
      host.appendChild(section);
      return;
    }
    const built = createTable([
      { label: '节点' },
      { label: '原因' },
      { label: '发起时间' },
      { label: '操作' },
    ]);
    uninstallRequests.forEach(function (req) {
      const tr = el('tr');
      tr.appendChild(cell(textOr(req.node_id), 'mono cell-ellipsis'));
      tr.appendChild(cell(textOr(req.reason)));
      tr.appendChild(cell(fmtTime(req.requested_at), 'cell-nowrap'));
      const td = el('td');
      td.appendChild(button('批准', {
        variant: 'primary',
        onClick: function () { approveUninstallRequest(req); },
      }));
      td.appendChild(button('拒绝', {
        variant: 'danger',
        onClick: function () { denyUninstallRequest(req); },
      }));
      tr.appendChild(td);
      built.tbody.appendChild(tr);
    });
    const wrap = el('div', 'table-wrap');
    wrap.appendChild(built.table);
    section.appendChild(wrap);
    host.appendChild(section);
  }

  async function approveUninstallRequest(req) {
    try {
      const res = await api('POST', '/uninstall-requests/' + encodeURIComponent(req.id) + '/approve', { signal: ac.signal });
      toast('已批准卸载请求。', 'success');
      await loadNodes({ silent: true });
      if (res && res.ticket) {
        showTicketDialog(
          '卸载挑战码',
          res.ticket,
          '已生成一次性挑战码。目标主机执行：sudo tg-agent uninstall --state-dir <状态目录> --ticket <挑战码>（10 分钟内有效）。'
        );
      }
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '审批失败。', 'error');
    }
  }

  async function denyUninstallRequest(req) {
    try {
      await api('POST', '/uninstall-requests/' + encodeURIComponent(req.id) + '/deny', { signal: ac.signal });
      toast('已拒绝卸载请求。', 'success');
      loadNodes({ silent: true });
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '拒绝失败。', 'error');
    }
  }

  async function requestNodeUninstall(node) {
    const label = textOr(node.hostname, node.id);
    const confirmed = await confirmDialog({
      title: '下发卸载',
      message: '确定从管理端卸载节点「' + label + '」的 Agent 吗？',
      detail: '系统会生成一次性挑战码并通过推送通道下发；节点在线时自动执行卸载，否则可在主机上用该挑战码手动执行。卸载后该节点将停止防护，证书与审计数据仍保留在控制面。',
      confirmText: '确认卸载',
      danger: true,
    });
    if (!confirmed) return;
    try {
      const res = await api('POST', '/nodes/' + encodeURIComponent(node.id) + '/uninstall', { signal: ac.signal });
      await loadNodes({ silent: true });
      if (res && res.ticket) {
        showTicketDialog(
          '卸载挑战码已下发',
          res.ticket,
          '节点在线时会自动卸载；若节点离线，可在主机上执行：sudo tg-agent uninstall --state-dir <状态目录> --ticket <挑战码>。挑战码 10 分钟内有效。'
        );
      }
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '下发卸载失败。', 'error');
    }
  }

  async function purgeNode(node) {
    const label = textOr(node.hostname, node.id);
    const confirmed = await confirmDialog({
      title: '删除节点',
      message: '从管理端删除节点「' + label + '」的记录？',
      detail: '仅删除控制面的节点记录与策略绑定；该节点当前已离线或已卸载，不会再上报。历史审计与卸载记录保留。',
      confirmText: '删除记录',
      danger: true,
    });
    if (!confirmed) return;
    try {
      await api('DELETE', '/nodes/' + encodeURIComponent(node.id) + '/record', { signal: ac.signal });
      toast('节点记录已删除。', 'success');
      await loadNodes({ silent: true });
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '删除节点失败。', 'error');
    }
  }

  async function purgeStaleNodes() {
    const stale = (Array.isArray(nodes) ? nodes : []).filter(function (n) {
      return n && (n.status === 'offline' || n.status === 'uninstalled');
    });
    if (!stale.length) {
      toast('没有可清理的离线或已卸载节点。', 'info');
      return;
    }
    const confirmed = await confirmDialog({
      title: '批量清理节点',
      message: '删除 ' + stale.length + ' 个离线/已卸载节点的记录？',
      detail: '仅删除控制面记录与策略绑定，历史审计保留。在线节点不会被删除。',
      confirmText: '全部删除',
      danger: true,
    });
    if (!confirmed) return;
    let failed = 0;
    for (const node of stale) {
      try {
        await api('DELETE', '/nodes/' + encodeURIComponent(node.id) + '/record', { signal: ac.signal });
      } catch (err) {
        if (isAborted(err)) return;
        failed += 1;
      }
    }
    toast(failed ? ('已清理 ' + (stale.length - failed) + ' 个，失败 ' + failed + ' 个。') : ('已清理 ' + stale.length + ' 个节点。'),
      failed ? 'error' : 'success');
    await loadNodes({ silent: true });
  }

  async function changeDegradedApproval(nodeId, approved) {
    try {
      await api('POST', '/nodes/' + encodeURIComponent(nodeId) + '/degraded-approval', {
        body: { approved: Boolean(approved) },
        signal: ac.signal,
      });
      toast(approved ? '已批准该节点的降级防护。' : '已撤销该节点的降级批准。', 'success');
      openNodeDrawer(nodeId);
      loadNodes({ silent: true });
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '降级审批操作失败。', 'error');
    }
  }

  async function revokeNode(node) {
    const label = textOr(node.hostname, node.id);
    const confirmed = await confirmDialog({
      title: '吊销节点身份',
      message: '确定吊销节点「' + label + '」的身份吗？',
      detail: '吊销后该节点的客户端证书将被拒绝，节点无法再上报心跳与审计记录。操作立即生效且不可撤销。',
      confirmText: '确认吊销',
      danger: true,
    });
    if (!confirmed) return;
    try {
      await api('DELETE', '/nodes/' + encodeURIComponent(node.id), { signal: ac.signal });
      toast('节点身份已吊销。', 'success');
      closeDrawerOnly();
      setHash('#/nodes');
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '节点吊销失败。', 'error');
    }
  }

  function renderNodeDetail(drawer, detail) {
    const payload = detail && typeof detail === 'object' ? detail : {};
    const node = payload.node && typeof payload.node === 'object' ? payload.node : payload;
    const recentAudit = Array.isArray(payload.recent_audit) ? payload.recent_audit : [];
    drawer.setTitle('节点 ' + textOr(node.hostname, node.id), textOr(node.id, ''));
    const body = drawer.body;
    clear(body);

    const statusMeta = NODE_STATUS_META[node.status] || { label: textOr(node.status), tone: 'muted' };
    const deg = degradedInfo(node);
    const summary = el('div', 'node-summary');
    summary.appendChild(badge(statusMeta.label, statusMeta.tone, textOr(node.status)));
    summary.appendChild(badge('enforcer: ' + enforcerLabel(node.enforcer), node.enforcer === 'observe' ? 'warn' : 'muted'));
    summary.appendChild(badge(deg.label, deg.tone));
    if (node.agent_version) summary.appendChild(badge('agent ' + node.agent_version, 'muted'));
    body.appendChild(summary);

    if (node.degraded) {
      const callout = el('div', 'callout ' + (node.degraded_approved ? 'callout--warn' : 'callout--danger'));
      callout.appendChild(el('div', 'callout__title', node.degraded_approved ? '该节点处于降级防护（已批准）' : '该节点处于降级防护（未审批）'));
      callout.appendChild(el('p', 'callout__text', node.degraded_approved
        ? '管理员已接受该节点当前的降级防护能力，请持续关注内核与 enforcer 状态。'
        : '内核能力不足时 enforcer 退化为受限防护，写入可能无法被完整拦截，需要管理员明确审批。'));
      body.appendChild(callout);
    }

    body.appendChild(el('h3', 'section-title', '基本信息'));
    body.appendChild(defList([
      { label: '节点 ID', value: textOr(node.id), mono: true },
      { label: '状态', value: statusMeta.label + '（' + textOr(node.status) + '）' },
      { label: '防护模式', value: enforcerLabel(node.enforcer) },
      { label: '节点角色', value: NODE_ROLE_LABELS[node.role] || textOr(node.role) },
      {
        label: '策略版本',
        value: node.policy_version !== undefined && node.policy_version !== null && Number(node.policy_version) > 0
          ? 'v' + node.policy_version
          : '—',
      },
      { label: '策略 ID', value: textOr(node.policy_id), mono: true },
      {
        label: '策略摘要',
        value: shortId(node.policy_digest, 12, 8),
        mono: true,
        title: textOr(node.policy_digest, ''),
      },
      { label: 'Agent 版本', value: textOr(node.agent_version) },
      { label: '最后心跳', value: fmtTime(node.last_seen) + (fmtAgo(node.last_seen) ? '（' + fmtAgo(node.last_seen) + '）' : '') },
      { label: '注册时间', value: fmtTime(node.enrolled_at) },
    ]));

    if (node.attestation && typeof node.attestation === 'object') {
      body.appendChild(el('h3', 'section-title', 'TPM 证明'));
      const att = node.attestation;
      body.appendChild(defList([
        { label: '状态', value: att.verified ? '已验证（TPM quote）' : '未验证' },
        { label: '验证时间', value: fmtTime(att.verified_at) },
        { label: 'PCR 选择', value: Array.isArray(att.indexes) ? att.indexes.join(', ') : '—', mono: true },
        { label: 'Quote 摘要', value: shortId(att.quote_sha, 12, 8), mono: true, title: textOr(att.quote_sha, '') },
      ]));
    }

    body.appendChild(el('h3', 'section-title', '能力探测'));
    const caps = node.caps && typeof node.caps === 'object' ? node.caps : null;
    if (!caps) {
      body.appendChild(el('p', 'muted', '节点尚未上报能力信息。'));
    } else {
      const capsBox = el('div', 'caps');
      [
        { label: 'bpf_lsm', key: 'bpf_lsm' },
        { label: 'fanotify', key: 'fanotify' },
        { label: 'btf', key: 'btf' },
      ].forEach(function (item) {
        const cap = el('div', 'cap-item');
        cap.appendChild(el('span', 'cap-item__label mono', item.label));
        const value = caps[item.key];
        if (value === true) cap.appendChild(badge('支持', 'ok'));
        else if (value === false) cap.appendChild(badge('不支持', 'danger'));
        else cap.appendChild(badge('未知', 'muted'));
        capsBox.appendChild(cap);
      });
      const kernelCap = el('div', 'cap-item');
      kernelCap.appendChild(el('span', 'cap-item__label', 'kernel_release'));
      kernelCap.appendChild(el('span', 'mono', textOr(caps.kernel_release)));
      capsBox.appendChild(kernelCap);
      [
        { label: 'boot_digest', key: 'boot_digest', short: true },
        { label: 'secure_boot', key: 'secure_boot' },
        { label: 'tpm', key: 'tpm' },
        { label: 'ima', key: 'ima' },
      ].forEach(function (item) {
        const cap = el('div', 'cap-item');
        cap.appendChild(el('span', 'cap-item__label mono', item.label));
        const value = caps[item.key];
        if (value === true) cap.appendChild(badge('是', 'ok'));
        else if (value === false) cap.appendChild(badge('否', 'muted'));
        else if (value) cap.appendChild(el('span', 'mono', item.short ? shortId(value, 12, 8) : String(value)));
        else cap.appendChild(badge('未知', 'muted'));
        capsBox.appendChild(cap);
      });
      body.appendChild(capsBox);
    }

    body.appendChild(el('h3', 'section-title', '审批与操作'));
    const actions = el('div', 'row-actions');
    if (node.degraded) {
      if (node.degraded_approved) {
        actions.appendChild(button('撤销降级批准', {
          onClick: function () {
            changeDegradedApproval(node.id, false);
          },
        }));
      } else {
        actions.appendChild(button('批准降级防护', {
          variant: 'primary',
          onClick: function () {
            changeDegradedApproval(node.id, true);
          },
        }));
      }
    } else {
      actions.appendChild(el('span', 'muted', '节点未处于降级状态，无需审批。'));
    }
    actions.appendChild(button('吊销节点身份', {
      variant: 'danger',
      onClick: function () {
        revokeNode(node);
      },
    }));
    if (node.role === 'protect') {
      actions.appendChild(button('下发卸载', {
        variant: 'danger-solid',
        onClick: function () {
          requestNodeUninstall(node);
        },
      }));
    }
    body.appendChild(actions);

    body.appendChild(el('h3', 'section-title', '最近审计'));
    if (recentAudit.length === 0) {
      body.appendChild(emptyBlock('暂无审计记录', '该节点尚未上报审计事件。'));
    } else {
      const built = createTable([
        { label: '时间' },
        { label: '类型' },
        { label: '路径' },
        { label: '结果' },
      ], 'data-table--compact');
      recentAudit.forEach(function (record) {
        const rec = record && typeof record === 'object' ? record : {};
        const tr = el('tr');
        tr.appendChild(cell(fmtTime(rec.ts), 'mono cell-nowrap'));
        tr.appendChild(cell(textOr(rec.kind), 'mono'));
        tr.appendChild(cell(textOr(rec.path), 'mono cell-ellipsis', textOr(rec.path)));
        const decisionRaw = typeof rec.decision === 'string' ? rec.decision.trim() : '';
        const decisionMeta = DECISION_META[decisionRaw];
        const td = el('td');
        if (decisionMeta) td.appendChild(badge(decisionMeta.label, decisionMeta.tone, decisionRaw));
        else td.appendChild(el('span', 'muted', decisionRaw || '—'));
        tr.appendChild(td);
        built.tbody.appendChild(tr);
      });
      const wrap = el('div', 'table-wrap');
      wrap.appendChild(built.table);
      body.appendChild(wrap);
    }
  }

  async function openNodeDrawer(nodeId) {
    if (destroyed) return;
    closeDrawerOnly();
    const drawer = createDrawer({
      title: '节点详情',
      subtitle: nodeId,
      onUserClose: function () {
        if (parseRoute().name === 'node-detail') setHash('#/nodes');
      },
    });
    drawer.body.appendChild(loadingBlock('正在加载节点详情…'));
    try {
      const detail = await api('GET', '/nodes/' + encodeURIComponent(nodeId), { signal: ac.signal });
      if (destroyed || !drawer.isOpen()) return;
      if (!detail || typeof detail !== 'object' || Array.isArray(detail)) {
        clear(drawer.body);
        drawer.body.appendChild(errorBlock('节点详情返回格式异常。', function () {
          openNodeDrawer(nodeId);
        }));
        return;
      }
      renderNodeDetail(drawer, detail);
    } catch (err) {
      if (isAborted(err) || destroyed || !drawer.isOpen()) return;
      clear(drawer.body);
      drawer.body.appendChild(errorBlock(err.message || '节点详情加载失败。', function () {
        openNodeDrawer(nodeId);
      }));
    }
  }

  return {
    async mount(host) {
      const filter = el('select', 'select select--auto');
      filter.setAttribute('aria-label', '按状态筛选节点');
      [
        { value: 'all', label: '全部状态' },
        { value: 'online', label: '仅在线' },
        { value: 'offline', label: '仅离线' },
        { value: 'uninstalled', label: '已卸载' },
        { value: 'degraded', label: '降级未审批' },
      ].forEach(function (option) {
        const node = el('option', null, option.label);
        node.value = option.value;
        filter.appendChild(node);
      });
      filter.addEventListener('change', function () {
        filterValue = filter.value;
        renderList();
      });

      host.appendChild(buildPageHead({
        title: '节点',
        desc: '节点心跳、防护模式与降级审批',
        actions: [
          filter,
          button('清理离线/已卸载', { onClick: function () { purgeStaleNodes(); } }),
          button('刷新', { onClick: function () { loadNodes(); } }),
        ],
      }));

      renderAgentInstallPanel(host);

      const panelRef = buildPanel('节点列表', { bodyClass: 'panel__body panel__body--flush' });
      const count = el('span', 'panel__meta', '');
      panelRef.head.appendChild(count);
      listRefs = { body: panelRef.body, count: count };
      host.appendChild(panelRef.panel);

      if (opts.id) openNodeDrawer(opts.id);
      await loadNodes();
    },
    destroy() {
      destroyed = true;
      ac.abort();
    },
  };
}

/* --------------------------------------------------------------------------
 * 策略列表
 * ------------------------------------------------------------------------ */

function policiesListView() {
  const ac = new AbortController();
  let destroyed = false;
  let loading = false;
  let policies = null;
  let refs = null;

  async function deletePolicy(policy) {
    const confirmed = await confirmDialog({
      title: '删除策略',
      message: '确定删除策略「' + textOr(policy.name, policy.id) + '」吗？',
      detail: '已分配到节点的策略无法删除（服务端会返回冲突）。删除后策略版本与签名记录不可恢复。',
      confirmText: '删除',
      danger: true,
    });
    if (!confirmed) return;
    try {
      await api('DELETE', '/policies/' + encodeURIComponent(policy.id), { signal: ac.signal });
      toast('策略已删除。', 'success');
      loadPolicies({ silent: true });
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '删除策略失败。', 'error');
    }
  }

  function policyRow(policy) {
    const tr = el('tr');

    const nameTd = el('td', 'cell-host');
    nameTd.appendChild(el('span', 'cell-host__name', textOr(policy.name, policy.id)));
    nameTd.appendChild(el('span', 'cell-host__id mono', textOr(policy.id)));
    tr.appendChild(nameTd);

    tr.appendChild(cell(policy.version === undefined || policy.version === null ? '—' : 'v' + policy.version, 'mono'));

    const paths = Array.isArray(policy.paths) ? policy.paths : [];
    const enforceCount = paths.filter(function (rule) { return rule && rule.mode === 'enforce'; }).length;
    const pathsTd = el('td');
    pathsTd.appendChild(el('span', null, paths.length + ' 条'));
    pathsTd.appendChild(el('span', 'cell-sub', enforceCount + ' 条 enforce'));
    tr.appendChild(pathsTd);

    const writers = Array.isArray(policy.writers) ? policy.writers : [];
    const processCount = writers.filter(function (writer) { return writer && writer.kind === 'process'; }).length;
    const writersTd = el('td');
    writersTd.appendChild(el('span', null, writers.length + ' 个'));
    if (processCount > 0) {
      writersTd.appendChild(el('span', 'cell-sub text-warn', '含 ' + processCount + ' 条 process 例外'));
    } else {
      writersTd.appendChild(el('span', 'cell-sub', '仅 publisher'));
    }
    tr.appendChild(writersTd);

    tr.appendChild(cell(fmtTime(policy.updated_at), 'mono cell-nowrap'));

    const actions = el('td', 'cell-actions');
    actions.appendChild(button('编辑', {
      variant: 'ghost',
      size: 'sm',
      onClick: function () {
        location.hash = '#/policies/' + encodeURIComponent(policy.id) + '/edit';
      },
    }));
    actions.appendChild(button('删除', {
      variant: 'ghost',
      size: 'sm',
      onClick: function () {
        deletePolicy(policy);
      },
    }));
    tr.appendChild(actions);
    return tr;
  }

  function renderPolicies() {
    if (!refs) return;
    clear(refs.body);
    const list = Array.isArray(policies) ? policies : [];
    refs.count.textContent = list.length + ' 个策略';
    if (list.length === 0) {
      refs.body.appendChild(emptyBlock('还没有策略', '点击右上角「新建策略」开始配置受保护路径。'));
      return;
    }
    const built = createTable([
      { label: '名称' },
      { label: '版本' },
      { label: '路径规则' },
      { label: '写入主体' },
      { label: '更新时间' },
      { label: '操作' },
    ]);
    list.forEach(function (policy) {
      built.tbody.appendChild(policyRow(policy));
    });
    const wrap = el('div', 'table-wrap');
    wrap.appendChild(built.table);
    refs.body.appendChild(wrap);
  }

  function renderError(message) {
    if (!refs) return;
    clear(refs.body);
    refs.body.appendChild(errorBlock(message, function () {
      loadPolicies();
    }));
    refs.count.textContent = '';
  }

  async function loadPolicies(loadOptions) {
    const settings = loadOptions || {};
    if (loading || destroyed) return;
    loading = true;
    if (!settings.silent && refs) {
      clear(refs.body);
      refs.body.appendChild(loadingBlock('正在加载策略…'));
    }
    try {
      const data = await api('GET', '/policies', { signal: ac.signal });
      if (destroyed) return;
      if (!Array.isArray(data)) {
        renderError('策略接口返回格式异常（期望数组）。');
        return;
      }
      policies = data;
      renderPolicies();
    } catch (err) {
      if (isAborted(err) || destroyed) return;
      renderError(err.message || '策略列表加载失败。');
    } finally {
      loading = false;
    }
  }

  return {
    async mount(host) {
      host.appendChild(buildPageHead({
        title: '策略',
        desc: '保护路径、允许写入主体与版本管理',
        actions: [
          button('新建策略', {
            variant: 'primary',
            onClick: function () {
              location.hash = '#/policies/new';
            },
          }),
        ],
      }));
      const panelRef = buildPanel('策略列表', { bodyClass: 'panel__body panel__body--flush' });
      refs = { body: panelRef.body, count: el('span', 'panel__meta', '') };
      panelRef.head.appendChild(refs.count);
      panelRef.head.appendChild(button('刷新', {
        variant: 'ghost',
        size: 'sm',
        onClick: function () {
          loadPolicies();
        },
      }));
      host.appendChild(panelRef.panel);
      await loadPolicies();
    },
    destroy() {
      destroyed = true;
      ac.abort();
    },
  };
}

/* --------------------------------------------------------------------------
 * 策略编辑器
 * ------------------------------------------------------------------------ */

function policyEditorView(options) {
  const opts = options || {};
  const isEdit = opts.mode === 'edit';
  const policyId = isEdit ? opts.id : '';
  const ac = new AbortController();
  let destroyed = false;
  let nodes = null;
  let nodesError = null;
  let saving = false;

  function renderEditorLoadError(host, message) {
    host.appendChild(buildPageHead({
      title: isEdit ? '编辑策略' : '新建策略',
      desc: '',
      actions: [
        button('返回列表', {
          variant: 'ghost',
          onClick: function () {
            setHash('#/policies');
          },
        }),
      ],
    }));
    const panelRef = buildPanel('加载失败', { bodyClass: 'panel__body' });
    panelRef.body.appendChild(errorBlock(message, function () {
      handleRoute();
    }));
    host.appendChild(panelRef.panel);
  }

  function renderEditor(host, policy) {
    const targetId = policy && policy.id ? String(policy.id) : policyId;
    const assignedIds = new Set();
    if (isEdit && Array.isArray(nodes)) {
      nodes.forEach(function (node) {
        if (node && node.id && String(node.policy_id || '') === targetId) assignedIds.add(String(node.id));
      });
    }

    const saveButtons = [];

    function createSaveButton() {
      const saveBtn = button('保存', {
        variant: 'primary',
        onClick: function () {
          savePolicy();
        },
      });
      saveButtons.push(saveBtn);
      return saveBtn;
    }

    const desc = isEdit
      ? '策略 ID：' + targetId + (policy && policy.version !== undefined ? ' · 当前版本 v' + policy.version : '')
      : '定义受保护路径、允许写入主体与分配节点';

    host.appendChild(buildPageHead({
      title: isEdit ? '编辑策略' : '新建策略',
      desc: desc,
      actions: [
        createSaveButton(),
        button('取消', {
          variant: 'ghost',
          onClick: function () {
            setHash('#/policies');
          },
        }),
      ],
    }));

    const form = el('form', 'policy-form');
    form.noValidate = true;
    const errorsBox = el('div', 'form-errors hidden');
    form.appendChild(errorsBox);

    /* 基本信息 */
    const basicPanel = buildPanel('基本信息', { bodyClass: 'panel__body' });
    const nameField = el('div', 'field');
    const nameLabel = el('label', 'label', '策略名称 ');
    nameLabel.setAttribute('for', 'policy-name');
    nameLabel.appendChild(el('span', 'req', '*'));
    const nameInput = el('input', 'input');
    nameInput.id = 'policy-name';
    nameInput.type = 'text';
    nameInput.maxLength = 128;
    nameInput.spellcheck = false;
    nameInput.placeholder = '例如：webroot';
    if (policy && typeof policy.name === 'string') nameInput.value = policy.name;
    nameField.append(nameLabel, nameInput);
    basicPanel.body.appendChild(nameField);
    form.appendChild(basicPanel.panel);

    /* 路径规则 */
    const addPathBtn = button('添加路径', {
      size: 'sm',
      onClick: function () {
        addPathRow();
      },
    });
    const pathsPanel = buildPanel('路径规则', {
      bodyClass: 'panel__body panel__body--flush',
      headNode: addPathBtn,
    });
    const pathTable = el('table', 'data-table rule-table');
    const pathHead = el('thead');
    const pathHeadRow = el('tr');
    ['受保护路径', '递归', '模式', '操作'].forEach(function (label) {
      pathHeadRow.appendChild(el('th', null, label));
    });
    pathHead.appendChild(pathHeadRow);
    const pathTbody = el('tbody');
    pathTable.append(pathHead, pathTbody);
    const pathWrap = el('div', 'table-wrap');
    pathWrap.appendChild(pathTable);
    pathsPanel.body.appendChild(pathWrap);
    pathsPanel.panel.appendChild(el('div', 'panel__foot', '路径必须是绝对路径，不允许包含 ".."；递归规则保护整棵子树，更具体的子路径规则优先。'));
    form.appendChild(pathsPanel.panel);

    /* 允许写入主体 */
    const addWriterBtn = button('添加主体', {
      size: 'sm',
      onClick: function () {
        addWriterRow();
      },
    });
    const writersPanel = buildPanel('允许写入主体', {
      bodyClass: 'panel__body panel__body--flush',
      headNode: addWriterBtn,
    });
    const writerTable = el('table', 'data-table writer-table');
    const writerHead = el('thead');
    const writerHeadRow = el('tr');
    ['类型', '标识', '操作'].forEach(function (label) {
      writerHeadRow.appendChild(el('th', null, label));
    });
    writerHead.appendChild(writerHeadRow);
    const writerTbody = el('tbody');
    writerTable.append(writerHead, writerTbody);
    const writerWrap = el('div', 'table-wrap');
    writerWrap.appendChild(writerTable);
    writersPanel.body.appendChild(writerWrap);
    writersPanel.panel.appendChild(el('div', 'panel__foot', 'publisher 按发布端身份授权；process 按可执行文件路径 + uid 授权，属于策略例外，应逐条评估。未添加任何主体时，enforce 规则会拒绝所有写入。'));
    form.appendChild(writersPanel.panel);

    /* 分配节点 */
    const nodePanel = buildPanel('分配节点', { bodyClass: 'panel__body' });
    const nodeGrid = el('div', 'node-grid');
    nodePanel.body.appendChild(nodeGrid);
    nodePanel.body.appendChild(el('p', 'field-hint', '勾选节点后保存，策略快照会下发到这些节点；保存会覆盖当前分配关系。'));
    form.appendChild(nodePanel.panel);

    const bottomActions = el('div', 'form-actions');
    bottomActions.appendChild(createSaveButton());
    bottomActions.appendChild(button('取消', {
      variant: 'ghost',
      onClick: function () {
        setHash('#/policies');
      },
    }));
    form.appendChild(bottomActions);

    host.appendChild(form);

    if (policy && Array.isArray(policy.paths) && policy.paths.length > 0) {
      policy.paths.forEach(function (rule) {
        addPathRow(rule);
      });
    } else {
      addPathRow();
    }
    if (policy && Array.isArray(policy.writers)) {
      policy.writers.forEach(function (writer) {
        addWriterRow(writer);
      });
    }
    renderNodePicker();

    function makePathRow(values) {
      const rule = values || {};
      const tr = el('tr');

      const pathTd = el('td');
      const pathInput = el('input', 'input');
      pathInput.type = 'text';
      pathInput.spellcheck = false;
      pathInput.placeholder = '/var/www/site';
      pathInput.dataset.field = 'path';
      if (rule.path) pathInput.value = String(rule.path);
      pathTd.appendChild(pathInput);
      tr.appendChild(pathTd);

      const recursiveTd = el('td');
      const recursiveLabel = el('label', 'checkbox');
      const recursiveInput = el('input');
      recursiveInput.type = 'checkbox';
      recursiveInput.dataset.field = 'recursive';
      recursiveInput.checked = rule.recursive !== false;
      recursiveLabel.append(recursiveInput, el('span', null, '递归'));
      recursiveTd.appendChild(recursiveLabel);
      tr.appendChild(recursiveTd);

      const modeTd = el('td');
      const modeSelect = el('select', 'select');
      modeSelect.dataset.field = 'mode';
      [
        { value: 'enforce', label: 'enforce（强制拦截）' },
        { value: 'observe', label: 'observe（仅观察）' },
      ].forEach(function (item) {
        const option = el('option', null, item.label);
        option.value = item.value;
        modeSelect.appendChild(option);
      });
      modeSelect.value = rule.mode === 'observe' ? 'observe' : 'enforce';
      modeTd.appendChild(modeSelect);
      tr.appendChild(modeTd);

      const actionTd = el('td', 'cell-actions');
      actionTd.appendChild(button('删除', {
        variant: 'ghost',
        size: 'sm',
        onClick: function () {
          tr.remove();
        },
      }));
      tr.appendChild(actionTd);
      return tr;
    }

    function addPathRow(values) {
      pathTbody.appendChild(makePathRow(values));
    }

    function makeWriterRow(values) {
      const writer = values || {};
      const tr = el('tr');

      const kindTd = el('td');
      const kindSelect = el('select', 'select');
      kindSelect.dataset.field = 'writer-kind';
      [
        { value: 'publisher', label: 'publisher（发布端）' },
        { value: 'process', label: 'process（主机进程）' },
      ].forEach(function (item) {
        const option = el('option', null, item.label);
        option.value = item.value;
        kindSelect.appendChild(option);
      });
      kindSelect.value = writer.kind === 'process' ? 'process' : 'publisher';
      kindTd.appendChild(kindSelect);
      tr.appendChild(kindTd);

      const fieldTd = el('td');
      const idFields = el('div', 'writer-fields writer-fields--id');
      const idInput = el('input', 'input');
      idInput.type = 'text';
      idInput.spellcheck = false;
      idInput.dataset.field = 'writer-id';
      idInput.placeholder = '发布端 ID，如 pub_1';
      if (writer.kind !== 'process' && writer.id) idInput.value = String(writer.id);
      idFields.appendChild(idInput);

      const processFields = el('div', 'writer-fields writer-fields--proc');
      const exeInput = el('input', 'input');
      exeInput.type = 'text';
      exeInput.spellcheck = false;
      exeInput.dataset.field = 'exe-path';
      exeInput.placeholder = '可执行文件路径，如 /usr/bin/rsync';
      if (writer.kind === 'process' && writer.exe_path) exeInput.value = String(writer.exe_path);
      const uidInput = el('input', 'input input--uid');
      uidInput.type = 'number';
      uidInput.min = '0';
      uidInput.step = '1';
      uidInput.dataset.field = 'uid';
      uidInput.placeholder = 'uid（可选）';
      if (writer.kind === 'process' && writer.uid !== undefined && writer.uid !== null) {
        uidInput.value = String(writer.uid);
      }
      processFields.append(exeInput, uidInput);

      fieldTd.append(idFields, processFields);
      tr.appendChild(fieldTd);

      const actionTd = el('td', 'cell-actions');
      actionTd.appendChild(button('删除', {
        variant: 'ghost',
        size: 'sm',
        onClick: function () {
          tr.remove();
        },
      }));
      tr.appendChild(actionTd);

      function syncFields() {
        const isProcess = kindSelect.value === 'process';
        idFields.classList.toggle('hidden', isProcess);
        processFields.classList.toggle('hidden', !isProcess);
      }
      kindSelect.addEventListener('change', syncFields);
      syncFields();
      return tr;
    }

    function addWriterRow(values) {
      writerTbody.appendChild(makeWriterRow(values));
    }

    function renderNodePicker() {
      clear(nodeGrid);
      if (nodes === null) {
        if (nodesError) {
          nodeGrid.appendChild(errorBlock(nodesError, function () {
            reloadNodes();
          }));
        } else {
          nodeGrid.appendChild(loadingBlock('正在加载节点…'));
        }
        return;
      }
      if (nodes.length === 0) {
        nodeGrid.appendChild(emptyBlock('暂无节点', '尚未纳管节点；可以先保存策略，之后再分配。'));
        return;
      }
      nodes.forEach(function (node) {
        if (!node || !node.id) return;
        const option = el('label', 'node-option');
        const checkbox = el('input');
        checkbox.type = 'checkbox';
        checkbox.value = String(node.id);
        checkbox.checked = assignedIds.has(String(node.id));
        checkbox.addEventListener('change', function () {
          if (checkbox.checked) assignedIds.add(String(node.id));
          else assignedIds.delete(String(node.id));
        });
        const textBox = el('span', 'node-option__text');
        textBox.appendChild(el('span', 'node-option__name', textOr(node.hostname, node.id)));
        textBox.appendChild(el('span', 'node-option__id mono', textOr(node.id)));
        option.append(checkbox, textBox);
        nodeGrid.appendChild(option);
      });
    }

    async function reloadNodes() {
      nodesError = null;
      nodes = null;
      renderNodePicker();
      try {
        const data = await api('GET', '/nodes', { signal: ac.signal });
        if (destroyed) return;
        if (!Array.isArray(data)) {
          nodesError = '节点接口返回格式异常（期望数组）。';
          nodes = null;
        } else {
          nodes = data;
          nodesError = null;
        }
      } catch (err) {
        if (isAborted(err) || destroyed) return;
        nodes = null;
        nodesError = err.message || '节点列表加载失败。';
      }
      renderNodePicker();
    }

    function clearFormErrors() {
      clear(errorsBox);
      errorsBox.classList.add('hidden');
      form.querySelectorAll('.is-invalid').forEach(function (node) {
        node.classList.remove('is-invalid');
      });
    }

    function showFormErrors(problems) {
      clear(errorsBox);
      errorsBox.classList.remove('hidden');
      errorsBox.appendChild(el('div', 'form-errors__title', '请修正以下 ' + problems.length + ' 个问题：'));
      const list = el('ul', 'form-errors__list');
      problems.forEach(function (problem) {
        list.appendChild(el('li', null, problem.msg));
        if (problem.field) problem.field.classList.add('is-invalid');
      });
      errorsBox.appendChild(list);
      errorsBox.scrollIntoView({ block: 'nearest' });
    }

    function collectPolicy() {
      const problems = [];
      const name = nameInput.value.trim();
      if (!name) problems.push({ msg: '策略名称不能为空。', field: nameInput });
      if (name.length > 128) problems.push({ msg: '策略名称不能超过 128 个字符。', field: nameInput });

      const paths = [];
      const seenPaths = new Map();
      const pathRows = Array.from(pathTbody.querySelectorAll('tr'));
      if (pathRows.length === 0) problems.push({ msg: '路径规则至少需要一条。', field: null });
      pathRows.forEach(function (tr, index) {
        const input = tr.querySelector('[data-field="path"]');
        const recursiveInput = tr.querySelector('[data-field="recursive"]');
        const modeSelect = tr.querySelector('[data-field="mode"]');
        const raw = input.value.trim();
        if (!raw) {
          problems.push({ msg: '路径规则 #' + (index + 1) + '：路径不能为空。', field: input });
        } else if (raw.charAt(0) !== '/') {
          problems.push({ msg: '路径规则 #' + (index + 1) + '：路径必须以 / 开头（绝对路径）。', field: input });
        } else if (raw.split('/').indexOf('..') !== -1) {
          problems.push({ msg: '路径规则 #' + (index + 1) + '：路径不允许包含 ".."。', field: input });
        } else if (seenPaths.has(raw)) {
          problems.push({
            msg: '路径规则 #' + (index + 1) + ' 与 #' + seenPaths.get(raw) + ' 重复。',
            field: input,
          });
        } else {
          seenPaths.set(raw, index + 1);
        }
        paths.push({
          path: raw,
          recursive: Boolean(recursiveInput.checked),
          mode: modeSelect.value === 'observe' ? 'observe' : 'enforce',
        });
      });

      const writers = [];
      const writerRows = Array.from(writerTbody.querySelectorAll('tr'));
      writerRows.forEach(function (tr, index) {
        const kindSelect = tr.querySelector('[data-field="writer-kind"]');
        const kind = kindSelect.value === 'process' ? 'process' : 'publisher';
        if (kind === 'publisher') {
          const idInput = tr.querySelector('[data-field="writer-id"]');
          const id = idInput.value.trim();
          if (!id) problems.push({ msg: '写入主体 #' + (index + 1) + '：publisher 需要填写发布端 ID。', field: idInput });
          writers.push({ kind: 'publisher', id: id });
        } else {
          const exeInput = tr.querySelector('[data-field="exe-path"]');
          const uidInput = tr.querySelector('[data-field="uid"]');
          const exePath = exeInput.value.trim();
          const uidRaw = uidInput.value.trim();
          if (!exePath) {
            problems.push({ msg: '写入主体 #' + (index + 1) + '：process 需要填写可执行文件路径。', field: exeInput });
          } else if (exePath.charAt(0) !== '/') {
            problems.push({ msg: '写入主体 #' + (index + 1) + '：exe_path 必须是绝对路径。', field: exeInput });
          }
          if (uidRaw && !/^\d+$/.test(uidRaw)) {
            problems.push({ msg: '写入主体 #' + (index + 1) + '：uid 必须是非负整数，或留空。', field: uidInput });
          }
          const writer = { kind: 'process', exe_path: exePath };
          if (uidRaw && /^\d+$/.test(uidRaw)) writer.uid = Number(uidRaw);
          writers.push(writer);
        }
      });

      const assignNodes = [];
      Array.from(nodeGrid.querySelectorAll('input[type="checkbox"]')).forEach(function (checkbox) {
        if (checkbox.checked) assignNodes.push(checkbox.value);
      });

      return { name: name, paths: paths, writers: writers, assign_nodes: assignNodes, problems: problems };
    }

    function setSaveBusy(busy) {
      saveButtons.forEach(function (saveBtn) {
        saveBtn.disabled = busy;
        saveBtn.textContent = busy ? '保存中…' : '保存';
      });
    }

    async function savePolicy() {
      if (saving) return;
      clearFormErrors();
      if (nodes === null) {
        showFormErrors([{
          msg: nodesError
            ? '节点列表加载失败，无法确认分配关系：' + nodesError
            : '节点列表尚未加载完成，请稍后重试。',
        }]);
        if (!nodesError) reloadNodes();
        return;
      }
      const result = collectPolicy();
      if (result.problems.length > 0) {
        showFormErrors(result.problems);
        toast('表单校验未通过，请检查标注项。', 'error');
        if (result.problems[0].field) result.problems[0].field.focus();
        return;
      }
      // 空主体列表只提示不阻塞（服务端允许），再确认一次避免误提交
      if (result.writers.length === 0) {
        const confirmed = await confirmDialog({
          title: '确认保存空写入主体列表',
          message: '当前策略没有任何允许写入的主体，enforce 模式下所有写入都会被拒绝。',
          detail: '如果这是预期配置（完全锁定写入），可以继续保存；否则请先添加 publisher 主体。',
          confirmText: '仍然保存',
        });
        if (!confirmed) return;
      }

      saving = true;
      setSaveBusy(true);
      try {
        const body = {
          name: result.name,
          paths: result.paths,
          writers: result.writers,
          assign_nodes: result.assign_nodes,
        };
        const response = isEdit
          ? await api('PUT', '/policies/' + encodeURIComponent(targetId), { body: body, signal: ac.signal })
          : await api('POST', '/policies', { body: body, signal: ac.signal });
        const versionRaw = response && typeof response === 'object' ? response.version : undefined;
        const version = versionRaw === undefined || versionRaw === null || !Number.isFinite(Number(versionRaw))
          ? null
          : Number(versionRaw);
        if (isEdit) {
          toast(version !== null ? '策略已保存，版本已递增至 v' + version + '。' : '策略已保存，版本已递增。', 'success');
        } else {
          toast(version !== null ? '策略已创建，当前版本 v' + version + '。' : '策略已创建。', 'success');
        }
        setHash('#/policies');
      } catch (err) {
        if (isAborted(err)) return;
        showFormErrors([{ msg: err.message || '保存策略失败。' }]);
        if (!err.handled) toast(err.message || '保存策略失败。', 'error');
      } finally {
        saving = false;
        setSaveBusy(false);
      }
    }
  }

  return {
    async mount(host) {
      clear(host);
      host.appendChild(loadingBlock(isEdit ? '正在加载策略…' : '正在加载节点列表…'));

      const results = await Promise.allSettled([
        isEdit
          ? api('GET', '/policies/' + encodeURIComponent(policyId), { signal: ac.signal })
          : Promise.resolve(null),
        api('GET', '/nodes', { signal: ac.signal }),
      ]);
      if (destroyed) return;
      clear(host);

      const nodesResult = results[1];
      if (nodesResult.status === 'fulfilled') {
        if (Array.isArray(nodesResult.value)) nodes = nodesResult.value;
        else nodesError = '节点接口返回格式异常（期望数组）。';
      } else if (!isAborted(nodesResult.reason)) {
        nodesError = nodesResult.reason && nodesResult.reason.message
          ? nodesResult.reason.message
          : '节点列表加载失败。';
      }

      if (isEdit) {
        const policyResult = results[0];
        if (policyResult.status === 'rejected') {
          if (isAborted(policyResult.reason)) return;
          renderEditorLoadError(host, policyResult.reason && policyResult.reason.message
            ? policyResult.reason.message
            : '策略加载失败。');
          return;
        }
        const policy = policyResult.value;
        if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
          renderEditorLoadError(host, '策略接口返回格式异常。');
          return;
        }
        renderEditor(host, policy);
      } else {
        renderEditor(host, null);
      }
    },
    destroy() {
      destroyed = true;
      ac.abort();
    },
  };
}

/* --------------------------------------------------------------------------
 * 发布
 * ------------------------------------------------------------------------ */

function publishView() {
  const ac = new AbortController();
  let destroyed = false;
  let nodes = null;
  let nodesError = null;
  let requests = [];
  let listLoading = false;
  let pendingReload = null;
  let statusFilter = '';
  let pollTimer = null;
  let creating = false;
  let refs = null;
  let syncProfiles = [];

  function nodeHostname(nodeId) {
    const list = Array.isArray(nodes) ? nodes : [];
    for (let i = 0; i < list.length; i += 1) {
      if (list[i] && String(list[i].id) === String(nodeId)) {
        return textOr(list[i].hostname, list[i].id || nodeId);
      }
    }
    return textOr(nodeId);
  }

  function publishNodes() {
    return (Array.isArray(nodes) ? nodes : []).filter(function (n) {
      return n && n.role === 'publish';
    });
  }

  function renderPublisherOptions() {
    if (!refs) return;
    const previous = refs.publisherSelect.value;
    clear(refs.publisherSelect);
    const placeholder = el('option', null, '请选择发布端');
    placeholder.value = '';
    refs.publisherSelect.appendChild(placeholder);
    publishNodes().forEach(function (node) {
      const option = el('option', null, textOr(node.hostname, node.id) + '（' + textOr(node.id) + '）');
      option.value = String(node.id);
      refs.publisherSelect.appendChild(option);
    });
    refs.publisherSelect.value = previous;
  }

  function renderEndpoints() {
    if (!refs || !refs.endpointsBody) return;
    const body = refs.endpointsBody;
    clear(body);
    const pubs = publishNodes();
    if (pubs.length === 0) {
      body.appendChild(el('p', 'muted', '尚未注册发布端。点击右上角「生成注册令牌」，在发布端主机执行注册命令；注册完成后这里会显示发布端及其心跳。'));
      return;
    }
    const built = createTable([
      { label: '主机名' },
      { label: '发布端 ID' },
      { label: '状态' },
      { label: '最后心跳' },
    ], 'data-table--compact');
    pubs.forEach(function (node) {
      const tr = el('tr');
      const hostTd = el('td', 'cell-host');
      hostTd.appendChild(el('span', 'cell-host__name', textOr(node.hostname, node.id)));
      hostTd.appendChild(el('span', 'cell-host__id mono', textOr(node.id)));
      tr.appendChild(hostTd);
      tr.appendChild(cell(textOr(node.id), 'mono cell-ellipsis'));
      const meta = NODE_STATUS_META[node.status] || { label: textOr(node.status), tone: 'muted' };
      tr.appendChild(cellNode(badge(meta.label, meta.tone)));
      tr.appendChild(cell(fmtTime(node.last_seen), 'cell-nowrap'));
      built.tbody.appendChild(tr);
    });
    const wrap = el('div', 'table-wrap');
    wrap.appendChild(built.table);
    body.appendChild(wrap);
  }

  async function issuePublishToken() {
    try {
      const res = await api('POST', '/bootstrap-tokens', { body: { role: 'publish' }, signal: ac.signal });
      const server = location.origin;
      const caURL = server + '/api/v1/downloads/agent?file=ca.crt';
      const command = 'tg-agent enroll --server ' + server + ' --bootstrap ' + res.token +
        ' --ca ca.crt --role publish --state-dir /var/lib/tamperguard-publish\n\n' +
        '# 注册完成后在发布端主机启动服务：\ntg-publish run --state-dir /var/lib/tamperguard-publish';
      showTicketDialog('发布端注册令牌', res.token,
        '令牌仅可使用一次。请把 CA 证书一起带到发布端主机，然后执行：\n' + command);
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '生成注册令牌失败。', 'error');
    }
  }

  function protectNodeList() {
    return (Array.isArray(nodes) ? nodes : []).filter(function (n) {
      return n && n.role !== 'publish';
    });
  }

  function renderSyncOptions() {
    if (!refs || !refs.syncPublisher) return;
    const pubs = publishNodes();
    const prot = protectNodeList();
    function fill(sel, list, placeholder) {
      if (!sel) return;
      const prev = sel.value;
      clear(sel);
      const opt = el('option', null, placeholder);
      opt.value = '';
      sel.appendChild(opt);
      list.forEach(function (n) {
        const o = el('option', null, textOr(n.hostname, n.id) + '（' + textOr(n.id) + '）');
        o.value = String(n.id);
        sel.appendChild(o);
      });
      sel.value = prev;
    }
    fill(refs.syncPublisher, pubs, '请选择发布端');
    fill(refs.syncNode, prot, '请选择目标节点');
  }

  function renderSyncProfiles() {
    if (!refs || !refs.syncBody) return;
    const body = refs.syncBody;
    clear(body);
    if (!syncProfiles.length) {
      body.appendChild(el('p', 'muted', '尚未配置同步任务。配置后，发布端只需执行 tg-publish sync 即可。'));
      return;
    }
    const built = createTable([
      { label: '发布端' },
      { label: '目标节点' },
      { label: '源目录' },
      { label: '目标目录' },
      { label: '模式' },
      { label: '方式' },
      { label: '最近执行' },
      { label: '操作' },
    ], 'data-table--compact');
    syncProfiles.forEach(function (sp) {
      const tr = el('tr');
      tr.appendChild(cell(textOr(sp.publisher_id), 'mono cell-ellipsis'));
      tr.appendChild(cell(textOr(sp.node_id), 'mono cell-ellipsis'));
      tr.appendChild(cell(textOr(sp.source_dir), 'mono cell-ellipsis', textOr(sp.source_dir)));
      tr.appendChild(cell(textOr(sp.target_dir), 'mono cell-ellipsis', textOr(sp.target_dir)));
      tr.appendChild(cell(sp.mode === 'incremental' ? '增量' : '全量'));
      tr.appendChild(cell(sp.delivery === 'local' ? '本机写入' : '跨机拉取'));
      const lastTd = el('td');
      if (sp.last_run_at) {
        lastTd.appendChild(el('span', 'cell-nowrap', fmtTime(sp.last_run_at)));
        const tone = sp.last_status === 'done' ? 'ok' : sp.last_status === 'failed' ? 'danger' : 'muted';
        lastTd.appendChild(el('span', 'cell-sub'));
        lastTd.appendChild(badge(sp.last_status || '—', tone));
      } else {
        lastTd.appendChild(el('span', 'muted', '未执行'));
      }
      tr.appendChild(lastTd);
      const td = el('td');
      td.appendChild(button('删除', {
        variant: 'ghost',
        size: 'sm',
        onClick: function () { deleteSyncProfile(sp); },
      }));
      tr.appendChild(td);
      built.tbody.appendChild(tr);
    });
    const wrap = el('div', 'table-wrap');
    wrap.appendChild(built.table);
    body.appendChild(wrap);
  }

  async function loadSyncProfiles() {
    try {
      const data = await api('GET', '/sync-profiles', { signal: ac.signal });
      syncProfiles = Array.isArray(data) ? data : [];
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      syncProfiles = [];
      toast(err.message || '加载同步配置失败。', 'error');
    }
    renderSyncProfiles();
  }

  async function saveSyncProfile(event) {
    event.preventDefault();
    const body = {
      publisher_id: refs.syncPublisher.value,
      node_id: refs.syncNode.value,
      source_dir: refs.syncSource.value.trim(),
      target_dir: refs.syncTarget.value.trim(),
      mode: refs.syncMode.value,
      delivery: refs.syncDelivery.value,
    };
    if (!body.publisher_id || !body.node_id || !body.source_dir || !body.target_dir) {
      toast('请填写发布端、目标节点、源目录和目标目录。', 'error');
      return;
    }
    try {
      await api('POST', '/sync-profiles', { body: body, signal: ac.signal });
      toast('同步配置已保存。发布端执行 tg-publish sync 即可触发。', 'success');
      refs.syncSource.value = '';
      refs.syncTarget.value = '';
      await loadSyncProfiles();
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '保存同步配置失败。', 'error');
    }
  }

  async function deleteSyncProfile(sp) {
    if (!window.confirm('删除这条同步配置？')) return;
    try {
      await api('DELETE', '/sync-profiles/' + encodeURIComponent(sp.id), { signal: ac.signal });
      toast('已删除。', 'success');
      await loadSyncProfiles();
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '删除失败。', 'error');
    }
  }

  function renderNodeOptions() {
    if (!refs) return;
    const previous = refs.nodeSelect.value;
    clear(refs.nodeSelect);
    const placeholder = el('option', null, '请选择被保护节点');
    placeholder.value = '';
    refs.nodeSelect.appendChild(placeholder);
    (Array.isArray(nodes) ? nodes : []).forEach(function (node) {
      if (!node || !node.id || node.role === 'publish') return;
      const option = el('option', null, textOr(node.hostname, node.id) + '（' + textOr(node.id) + '）');
      option.value = String(node.id);
      refs.nodeSelect.appendChild(option);
    });
    refs.nodeSelect.value = previous;
    renderPublisherOptions();
    renderEndpoints();
    renderSyncOptions();

    const errorBox = refs.nodesError;
    clear(errorBox);
    errorBox.classList.add('hidden');
    if (nodesError) {
      errorBox.classList.remove('hidden');
      errorBox.appendChild(el('span', null, '节点列表加载失败：' + nodesError));
      errorBox.appendChild(button('重试', {
        variant: 'ghost',
        size: 'sm',
        onClick: function () {
          nodesError = null;
          loadNodes();
        },
      }));
    } else if (nodes && nodes.length === 0) {
      errorBox.classList.remove('hidden');
      errorBox.appendChild(el('span', null, '尚未纳管节点，暂时无法创建发布请求。'));
    }
  }

  async function loadNodes() {
    try {
      const data = await api('GET', '/nodes', { signal: ac.signal });
      if (destroyed) return;
      if (!Array.isArray(data)) {
        nodes = null;
        nodesError = '节点接口返回格式异常（期望数组）。';
      } else {
        nodes = data;
        nodesError = null;
      }
    } catch (err) {
      if (isAborted(err) || destroyed) return;
      nodes = null;
      nodesError = err.message || '节点列表加载失败。';
    }
    renderNodeOptions();
  }

  function setRefreshMeta(text, warn) {
    if (!refs) return;
    refs.refreshMeta.textContent = text;
    refs.refreshMeta.classList.toggle('text-warn', Boolean(warn));
  }

  function clearFormErrors() {
    refs.form.querySelectorAll('.field-error').forEach(function (node) {
      node.textContent = '';
      node.classList.add('hidden');
    });
    refs.form.querySelectorAll('.is-invalid').forEach(function (node) {
      node.classList.remove('is-invalid');
    });
    refs.formError.textContent = '';
    refs.formError.classList.add('hidden');
  }

  function setFieldError(key, message) {
    const errorNode = refs.form.querySelector('[data-error-for="' + key + '"]');
    if (errorNode) {
      errorNode.textContent = message || '';
      errorNode.classList.toggle('hidden', !message);
    }
    const inputs = {
      node_id: refs.nodeSelect,
      publisher_id: refs.publisherInput,
      source_dir: refs.sourceDirInput,
      target_dir: refs.targetInput,
    };
    const input = inputs[key];
    if (input) input.classList.toggle('is-invalid', Boolean(message));
  }

  function renderRequestsError(message) {
    if (!refs) return;
    clear(refs.listBody);
    refs.listBody.appendChild(errorBlock(message, function () {
      loadRequests();
    }));
    refs.count.textContent = '';
  }

  function requestRow(request) {
    const req = request && typeof request === 'object' ? request : {};
    const tr = el('tr');
    tr.appendChild(cell(shortId(req.id, 12, 8), 'mono cell-nowrap', textOr(req.id)));

    const nodeTd = el('td', 'cell-host');
    nodeTd.appendChild(el('span', 'cell-host__name', nodeHostname(req.node_id)));
    nodeTd.appendChild(el('span', 'cell-host__id mono', textOr(req.node_id)));
    tr.appendChild(nodeTd);

    tr.appendChild(cell(textOr(req.publisher_id), 'mono cell-nowrap'));
    const deliveryPull = String(req.delivery || 'local') === 'pull';
    tr.appendChild(cellNode(badge(deliveryPull ? '跨机拉取' : '本机写入', deliveryPull ? 'info' : 'muted')));
    const incr = String(req.mode || 'full') === 'incremental';
    tr.appendChild(cellNode(badge(incr ? '增量' : '全量', incr ? 'ok' : 'muted')));
    const verifyTd = el('td');
    if (req.verify_digest && req.verify_digest === req.manifest) {
      verifyTd.appendChild(badge('通过 ' + (req.verified_files || 0), 'ok'));
    } else if (req.verify_digest) {
      verifyTd.appendChild(badge('不一致', 'danger'));
    } else {
      verifyTd.appendChild(el('span', 'muted', '—'));
    }
    tr.appendChild(verifyTd);
    tr.appendChild(cell(textOr(req.source_dir), 'mono cell-ellipsis', textOr(req.source_dir)));

    const statusMeta = PUBLISH_STATUS_META[req.status] || { label: textOr(req.status), tone: 'muted' };
    tr.appendChild(cellNode(badge(statusMeta.label, statusMeta.tone, textOr(req.status))));

    tr.appendChild(cell(textOr(req.note), 'cell-ellipsis', textOr(req.note, '')));

    const actions = el('td', 'cell-actions');
    if (req.status === 'pending' || req.status === 'manifest_received') {
      actions.appendChild(button('取消', {
        variant: 'ghost',
        size: 'sm',
        onClick: function () {
          cancelRequest(req);
        },
      }));
    } else {
      actions.appendChild(el('span', 'muted', '—'));
    }
    tr.appendChild(actions);
    return tr;
  }

  function renderRequests() {
    if (!refs) return;
    clear(refs.listBody);
    const list = Array.isArray(requests) ? requests : [];
    refs.count.textContent = list.length + ' 条';
    if (list.length === 0) {
      const filteredMeta = PUBLISH_STATUS_META[statusFilter];
      refs.listBody.appendChild(emptyBlock(
        filteredMeta ? '没有处于「' + filteredMeta.label + '」状态的请求' : '还没有发布请求',
        filteredMeta ? '切换状态筛选查看其他请求。' : '在上方创建发布请求后，等待发布端处理。'
      ));
      return;
    }
    const built = createTable([
      { label: '请求 ID' },
      { label: '节点' },
      { label: '发布端' },
      { label: '方式' },
      { label: '模式' },
      { label: '校验' },
      { label: '源目录' },
      { label: '状态' },
      { label: '备注' },
      { label: '操作' },
    ]);
    list.forEach(function (request) {
      built.tbody.appendChild(requestRow(request));
    });
    const wrap = el('div', 'table-wrap');
    wrap.appendChild(built.table);
    refs.listBody.appendChild(wrap);
  }

  async function loadRequests(loadOptions) {
    const settings = loadOptions || {};
    if (destroyed) return;
    if (listLoading) {
      // 已有请求在途时排队一次，避免筛选切换被静默忽略
      pendingReload = settings;
      return;
    }
    listLoading = true;
    if (!settings.silent && refs) {
      clear(refs.listBody);
      refs.listBody.appendChild(loadingBlock('正在加载发布请求…'));
    }
    try {
      const query = statusFilter ? { status: statusFilter } : undefined;
      const data = await api('GET', '/publish-requests', { query: query, signal: ac.signal });
      if (destroyed) return;
      if (!Array.isArray(data)) {
        if (settings.silent) setRefreshMeta('自动刷新失败：响应格式异常', true);
        else renderRequestsError('发布请求接口返回格式异常（期望数组）。');
        return;
      }
      requests = data;
      renderRequests();
      setRefreshMeta('最近刷新 ' + clockNow(), false);
    } catch (err) {
      if (isAborted(err) || destroyed) return;
      if (settings.silent) {
        // 轮询失败不弹 toast，避免每 5 秒打扰；状态行提示即可
        setRefreshMeta('自动刷新失败，将在 5 秒后重试', true);
      } else {
        renderRequestsError(err.message || '发布请求加载失败。');
      }
    } finally {
      listLoading = false;
      if (pendingReload) {
        const next = pendingReload;
        pendingReload = null;
        loadRequests(next);
      }
    }
  }

  async function cancelRequest(request) {
    const confirmed = await confirmDialog({
      title: '取消发布请求',
      message: '确定取消发布请求 ' + textOr(request.id) + ' 吗？',
      detail: '仅 pending / manifest_received 状态可以取消；已签发令牌的请求需要走吊销流程。',
      confirmText: '取消请求',
      danger: true,
    });
    if (!confirmed) return;
    try {
      await api('POST', '/publish-requests/' + encodeURIComponent(request.id) + '/cancel', { signal: ac.signal });
      toast('发布请求已取消。', 'success');
      loadRequests({ silent: true });
    } catch (err) {
      if (isAborted(err) || err.handled) return;
      toast(err.message || '取消发布请求失败。', 'error');
    }
  }

  async function createRequest(event) {
    event.preventDefault();
    if (creating) return;
    clearFormErrors();

    const values = {
      node_id: refs.nodeSelect.value,
      publisher_id: refs.publisherInput.value.trim(),
      source_dir: refs.sourceDirInput.value.trim(),
      target_dir: refs.targetInput.value.trim(),
      note: refs.noteInput.value.trim(),
      delivery: refs.deliverySelect.value,
      mode: refs.modeSelect.value,
    };
    const problems = [];
    if (!values.node_id) problems.push({ key: 'node_id', message: '请选择目标节点。' });
    if (!values.publisher_id) problems.push({ key: 'publisher_id', message: '请输入发布端 ID。' });
    if (!values.source_dir) problems.push({ key: 'source_dir', message: '请输入源目录。' });
    if (!values.target_dir) problems.push({ key: 'target_dir', message: '请输入目标目录。' });
    if (problems.length > 0) {
      problems.forEach(function (problem) {
        setFieldError(problem.key, problem.message);
      });
      const firstInvalid = refs.form.querySelector('.is-invalid');
      if (firstInvalid) firstInvalid.focus();
      return;
    }

    creating = true;
    refs.submitBtn.disabled = true;
    refs.submitBtn.textContent = '创建中…';
    try {
      const response = await api('POST', '/publish-requests', { body: values, signal: ac.signal });
      const requestId = response && typeof response === 'object' && response.id ? String(response.id) : '';
      toast(requestId
        ? '发布请求已创建（' + requestId + '），等待发布端处理。'
        : '发布请求已创建，等待发布端处理。', 'success');
      refs.publisherInput.value = '';
      refs.publisherSelect.value = '';
      refs.targetInput.value = '';
      if (refs.deliverySelect) refs.deliverySelect.value = 'local';
      if (refs.modeSelect) refs.modeSelect.value = 'full';
      refs.sourceDirInput.value = '';
      refs.noteInput.value = '';
      refs.nodeSelect.value = '';
      await loadRequests({ silent: true });
    } catch (err) {
      if (isAborted(err)) return;
      const message = err.message || '创建发布请求失败。';
      refs.formError.textContent = message;
      refs.formError.classList.remove('hidden');
      if (!err.handled) toast(message, 'error');
    } finally {
      creating = false;
      refs.submitBtn.disabled = false;
      refs.submitBtn.textContent = '创建请求';
    }
  }

  function tick() {
    if (destroyed) return;
    // 页面不可见时暂停轮询，恢复可见时立即补一次
    if (document.visibilityState !== 'visible') return;
    loadRequests({ silent: true });
  }

  function onVisibilityChange() {
    if (document.visibilityState === 'visible') loadRequests({ silent: true });
  }

  return {
    async mount(host) {
      host.appendChild(buildPageHead({
        title: '发布',
        desc: '创建发布请求并跟踪发布端处理进度',
        actions: [
          el('span', 'page-head__note', '列表每 5 秒自动刷新（仅页面可见时）'),
          button('刷新', { onClick: function () { loadRequests(); } }),
        ],
      }));

      const endpointsPanel = buildPanel('发布端', { bodyClass: 'panel__body' });
      endpointsPanel.head.appendChild(button('生成注册令牌', {
        variant: 'primary',
        size: 'sm',
        onClick: function () { issuePublishToken(); },
      }));
      host.appendChild(endpointsPanel.panel);

      const syncPanel = buildPanel('同步配置（管理端定义，发布端只触发）', { bodyClass: 'panel__body' });
      syncPanel.body.innerHTML = SYNC_PROFILE_HTML;
      const syncBody = el('div', '');
      syncPanel.body.appendChild(syncBody);
      host.appendChild(syncPanel.panel);

      const formPanel = buildPanel('新建发布请求', { bodyClass: 'panel__body' });
      formPanel.body.innerHTML = PUBLISH_FORM_HTML; // 静态骨架
      host.appendChild(formPanel.panel);

      const listPanel = buildPanel('发布请求', { bodyClass: 'panel__body panel__body--flush' });
      const statusSelect = el('select', 'select select--auto');
      statusSelect.setAttribute('aria-label', '按状态筛选发布请求');
      const allOption = el('option', null, '全部状态');
      allOption.value = '';
      statusSelect.appendChild(allOption);
      PUBLISH_FILTER_STATUSES.forEach(function (status) {
        const meta = PUBLISH_STATUS_META[status];
        const option = el('option', null, meta.label);
        option.value = status;
        statusSelect.appendChild(option);
      });
      const count = el('span', 'panel__meta', '');
      listPanel.head.append(statusSelect, count);
      const foot = el('div', 'panel__foot');
      const refreshMeta = el('span', 'panel__meta', '自动刷新已启用');
      foot.appendChild(refreshMeta);
      listPanel.panel.appendChild(foot);
      host.appendChild(listPanel.panel);

      const form = formPanel.body.querySelector('#pub-form');
      refs = {
        form: form,
        nodeSelect: form.querySelector('#pub-node'),
        publisherInput: form.querySelector('#pub-publisher'),
        publisherSelect: form.querySelector('#pub-publisher'),
        deliverySelect: form.querySelector('#pub-delivery'),
        modeSelect: form.querySelector('#pub-mode'),
        endpointsBody: endpointsPanel.body,
        syncBody: syncBody,
        syncPublisher: syncPanel.body.querySelector('#sp-publisher'),
        syncNode: syncPanel.body.querySelector('#sp-node'),
        syncSource: syncPanel.body.querySelector('#sp-source'),
        syncTarget: syncPanel.body.querySelector('#sp-target'),
        syncMode: syncPanel.body.querySelector('#sp-mode'),
        syncDelivery: syncPanel.body.querySelector('#sp-delivery'),
        sourceDirInput: form.querySelector('#pub-source'),
        targetInput: form.querySelector('#pub-target'),
        noteInput: form.querySelector('#pub-note'),
        submitBtn: form.querySelector('#pub-submit'),
        formError: form.querySelector('#pub-form-error'),
        nodesError: form.querySelector('#pub-nodes-error'),
        listBody: listPanel.body,
        count: count,
        refreshMeta: refreshMeta,
      };

      form.addEventListener('submit', createRequest);
      const syncForm = syncPanel.body.querySelector('#sync-form');
      if (syncForm) syncForm.addEventListener('submit', saveSyncProfile);
      renderSyncOptions();
      loadSyncProfiles();
      statusSelect.addEventListener('change', function () {
        statusFilter = statusSelect.value;
        loadRequests();
      });
      document.addEventListener('visibilitychange', onVisibilityChange);

      await Promise.all([loadNodes(), loadRequests()]);
      if (destroyed) return;
      pollTimer = setInterval(tick, PUBLISH_POLL_MS);
    },
    destroy() {
      destroyed = true;
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = null;
      document.removeEventListener('visibilitychange', onVisibilityChange);
      ac.abort();
    },
  };
}

/* --------------------------------------------------------------------------
 * 审计
 * ------------------------------------------------------------------------ */

function auditView() {
  const ac = new AbortController();
  let destroyed = false;
  let records = [];
  let beforeSeq = null;
  let hasMore = true;
  let loading = false;
  let pendingReset = false;
  let nodes = null;
  let refs = null;

  function appendNodeOptions() {
    if (!refs) return;
    const previous = refs.nodeSelect.value;
    clear(refs.nodeSelect);
    const allOption = el('option', null, '全部节点');
    allOption.value = '';
    refs.nodeSelect.appendChild(allOption);
    (Array.isArray(nodes) ? nodes : []).forEach(function (node) {
      if (!node || !node.id) return;
      const option = el('option', null, textOr(node.hostname, node.id) + '（' + textOr(node.id) + '）');
      option.value = String(node.id);
      refs.nodeSelect.appendChild(option);
    });
    refs.nodeSelect.value = previous;

    if (nodes === null) {
      refs.nodeHint.classList.remove('hidden');
      refs.nodeHint.textContent = '节点列表加载失败，节点筛选暂不可用。';
    } else {
      refs.nodeHint.classList.add('hidden');
    }
  }

  async function loadNodes() {
    try {
      const data = await api('GET', '/nodes', { signal: ac.signal });
      if (destroyed) return;
      if (Array.isArray(data)) nodes = data;
      else nodes = null;
    } catch (err) {
      if (isAborted(err) || destroyed) return;
      nodes = null;
    }
    appendNodeOptions();
  }

  function updateFooter() {
    if (!refs) return;
    refs.count.textContent = '已加载 ' + records.length + ' 条';
    const showMore = hasMore && records.length > 0;
    refs.loadMoreBtn.classList.toggle('hidden', !showMore);
    refs.endNote.classList.toggle('hidden', !(records.length > 0 && !hasMore));
  }

  function renderAudit() {
    if (!refs) return;
    clear(refs.tableHost);
    const filtered = Boolean(refs.nodeSelect.value || refs.kindSelect.value);
    if (records.length === 0) {
      refs.tableHost.appendChild(emptyBlock(
        filtered ? '没有符合条件的审计记录' : '暂无审计记录',
        filtered ? '调整节点或类型筛选后重试。' : '节点上报审计事件后会显示在这里。'
      ));
      updateFooter();
      return;
    }
    const built = createAuditTable();
    records.forEach(function (record) {
      built.tbody.appendChild(auditRow(record));
    });
    const wrap = el('div', 'table-wrap');
    wrap.appendChild(built.table);
    refs.tableHost.appendChild(wrap);
    updateFooter();
  }

  function renderLoadError(message) {
    clear(refs.tableHost);
    refs.tableHost.appendChild(errorBlock(message, function () {
      loadAudit({ reset: true });
    }));
    refs.count.textContent = '';
    refs.loadMoreBtn.classList.add('hidden');
    refs.endNote.classList.add('hidden');
  }

  async function loadAudit(loadOptions) {
    const settings = loadOptions || {};
    const reset = settings.reset === true;
    if (loading) {
      if (reset) pendingReset = true;
      return;
    }
    loading = true;
    if (reset) {
      records = [];
      beforeSeq = null;
      hasMore = true;
    }
    if (refs) {
      if (reset) {
        clear(refs.tableHost);
        refs.tableHost.appendChild(loadingBlock('正在加载审计记录…'));
        refs.loadMoreBtn.classList.add('hidden');
        refs.endNote.classList.add('hidden');
        refs.count.textContent = '';
      } else {
        refs.loadMoreBtn.disabled = true;
        refs.loadMoreBtn.textContent = '加载中…';
      }
    }

    const limit = Number(refs.limitSelect.value) || 50;
    const query = { limit: limit };
    if (refs.nodeSelect.value) query.node_id = refs.nodeSelect.value;
    if (refs.kindSelect.value) query.kind = refs.kindSelect.value;
    if (!reset && beforeSeq !== null) query.before_seq = beforeSeq;

    try {
      const data = await api('GET', '/audit', { query: query, signal: ac.signal });
      if (destroyed || !refs) return;
      if (!Array.isArray(data)) {
        renderLoadError('审计接口返回格式异常（期望数组）。');
        return;
      }
      records = reset ? data.slice() : records.concat(data);
      const last = data.length > 0 ? data[data.length - 1] : null;
      const lastSeq = last && last.seq !== undefined && last.seq !== null && Number.isFinite(Number(last.seq))
        ? Number(last.seq)
        : null;
      if (lastSeq !== null) beforeSeq = lastSeq;
      hasMore = data.length >= limit && lastSeq !== null;
      renderAudit();
    } catch (err) {
      if (isAborted(err) || destroyed) return;
      const message = err.message || '审计记录加载失败。';
      if (reset || records.length === 0) {
        renderLoadError(message);
      } else {
        toast(message, 'error');
      }
    } finally {
      loading = false;
      if (refs) {
        refs.loadMoreBtn.disabled = false;
        refs.loadMoreBtn.textContent = '加载更多';
      }
      if (pendingReset) {
        pendingReset = false;
        loadAudit({ reset: true });
      }
    }
  }

  function renderVerifyResult(result) {
    if (!refs) return;
    const box = refs.verifyResult;
    clear(box);
    box.classList.remove('hidden');
    const data = result && typeof result === 'object' && !Array.isArray(result) ? result : {};
    const ok = data.ok === true;
    const failed = data.ok === false;
    box.className = 'verify-panel ' + (ok ? 'verify-panel--ok' : failed ? 'verify-panel--danger' : 'verify-panel--warn');

    const head = el('div', 'verify-panel__head');
    head.appendChild(el('span', 'verify-panel__title', ok
      ? '审计链校验通过'
      : failed
        ? '审计链校验失败'
        : '校验完成（响应缺少 ok 字段）'));
    box.appendChild(head);

    const descriptions = [];
    const badSeqRaw = data.first_bad_seq !== undefined
      ? data.first_bad_seq
      : (data.bad_seq !== undefined ? data.bad_seq : undefined);
    if (failed && badSeqRaw !== undefined) descriptions.push('首个异常序号：' + textOr(badSeqRaw));
    if (typeof data.message === 'string' && data.message.trim()) descriptions.push(data.message.trim());
    if (typeof data.error === 'string' && data.error.trim()) descriptions.push('错误码：' + data.error.trim());
    if (descriptions.length > 0) {
      box.appendChild(el('p', 'verify-panel__text', descriptions.join('；')));
    }

    const details = el('details', 'verify-panel__details');
    details.appendChild(el('summary', null, '原始响应'));
    const pre = el('pre', 'code-block');
    pre.textContent = JSON.stringify(result, null, 2);
    details.appendChild(pre);
    box.appendChild(details);
  }

  async function verifyChain() {
    if (!refs.nodeSelect.value) {
      toast('请先选择一个节点，再验证该节点的审计链。', 'error');
      return;
    }
    refs.verifyBtn.disabled = true;
    refs.verifyBtn.textContent = '校验中…';
    try {
      const result = await api('GET', '/audit/verify', {
        query: { node_id: refs.nodeSelect.value },
        signal: ac.signal,
      });
      if (destroyed) return;
      renderVerifyResult(result);
    } catch (err) {
      if (isAborted(err) || destroyed) return;
      const box = refs.verifyResult;
      clear(box);
      box.className = 'verify-panel verify-panel--danger';
      const head = el('div', 'verify-panel__head');
      head.appendChild(el('span', 'verify-panel__title', '审计链校验失败'));
      box.appendChild(head);
      box.appendChild(el('p', 'verify-panel__text', err.message || '校验请求失败。'));
    } finally {
      refs.verifyBtn.disabled = false;
      refs.verifyBtn.textContent = '验证审计链';
    }
  }

  return {
    async mount(host) {
      host.appendChild(buildPageHead({
        title: '审计',
        desc: '链式审计记录查询与完整性校验',
      }));

      const filterBar = el('div', 'filter-bar');
      filterBar.innerHTML = AUDIT_FILTER_HTML; // 静态骨架
      host.appendChild(filterBar);

      const verifyResult = el('div', 'verify-panel hidden');
      host.appendChild(verifyResult);

      const panelRef = buildPanel('审计记录', { bodyClass: 'panel__body panel__body--flush' });
      const count = el('span', 'panel__meta', '');
      panelRef.head.appendChild(count);
      const tableHost = el('div');
      panelRef.body.appendChild(tableHost);
      const foot = el('div', 'panel__foot panel__foot--between');
      const footGroup = el('div', 'panel__foot-group');
      const endNote = el('span', 'panel__meta hidden', '已加载全部记录');
      const loadMoreBtn = button('加载更多', {
        variant: 'ghost',
        size: 'sm',
        onClick: function () {
          loadAudit({ reset: false });
        },
      });
      footGroup.append(endNote);
      foot.append(footGroup, loadMoreBtn);
      panelRef.panel.appendChild(foot);
      host.appendChild(panelRef.panel);

      const nodeSelect = filterBar.querySelector('#aud-node');
      const kindSelect = filterBar.querySelector('#aud-kind');
      const limitSelect = filterBar.querySelector('#aud-limit');
      const nodeHint = filterBar.querySelector('#aud-node-hint');
      const verifyBtn = filterBar.querySelector('#aud-verify');
      const refreshBtn = filterBar.querySelector('#aud-refresh');

      const allKinds = el('option', null, '全部类型');
      allKinds.value = '';
      kindSelect.appendChild(allKinds);
      AUDIT_KINDS.forEach(function (kind) {
        const label = AUDIT_KIND_LABELS[kind] || kind;
        const option = el('option', null, kind + '（' + label + '）');
        option.value = kind;
        kindSelect.appendChild(option);
      });

      refs = {
        nodeSelect: nodeSelect,
        kindSelect: kindSelect,
        limitSelect: limitSelect,
        nodeHint: nodeHint,
        verifyBtn: verifyBtn,
        verifyResult: verifyResult,
        tableHost: tableHost,
        count: count,
        endNote: endNote,
        loadMoreBtn: loadMoreBtn,
      };

      refreshBtn.addEventListener('click', function () {
        loadAudit({ reset: true });
      });
      verifyBtn.addEventListener('click', verifyChain);
      [nodeSelect, kindSelect, limitSelect].forEach(function (select) {
        select.addEventListener('change', function () {
          loadAudit({ reset: true });
        });
      });

      await Promise.all([loadNodes(), loadAudit({ reset: true })]);
    },
    destroy() {
      destroyed = true;
      ac.abort();
    },
  };
}

/* --------------------------------------------------------------------------
 * 吊销
 * ------------------------------------------------------------------------ */

function revocationsView() {
  const ac = new AbortController();
  let destroyed = false;
  let revocations = [];
  let loading = false;
  let submitting = false;
  let refs = null;

  function updateKindHint() {
    const meta = REVOCATION_KIND_META[refs.kindSelect.value] || {};
    refs.kindHint.textContent = meta.hint || '';
    refs.valueInput.placeholder = meta.hint || '填写要吊销的值';
  }

  function clearErrors() {
    refs.form.querySelectorAll('.field-error').forEach(function (node) {
      node.textContent = '';
      node.classList.add('hidden');
    });
    refs.form.querySelectorAll('.is-invalid').forEach(function (node) {
      node.classList.remove('is-invalid');
    });
    refs.formError.textContent = '';
    refs.formError.classList.add('hidden');
  }

  function setFieldError(key, message) {
    const errorNode = refs.form.querySelector('[data-error-for="' + key + '"]');
    if (errorNode) {
      errorNode.textContent = message || '';
      errorNode.classList.toggle('hidden', !message);
    }
    const inputs = { value: refs.valueInput, reason: refs.reasonInput };
    const input = inputs[key];
    if (input) input.classList.toggle('is-invalid', Boolean(message));
  }

  function renderError(message) {
    if (!refs) return;
    clear(refs.body);
    refs.body.appendChild(errorBlock(message, function () {
      loadRevocations();
    }));
    refs.count.textContent = '';
  }

  function renderRevocations() {
    if (!refs) return;
    clear(refs.body);
    refs.count.textContent = revocations.length + ' 条';
    if (revocations.length === 0) {
      refs.body.appendChild(emptyBlock('当前没有吊销记录', '通过上方表单提交吊销后，会在这里显示。'));
      return;
    }
    const built = createTable([
      { label: '类型' },
      { label: '值' },
      { label: '原因' },
      { label: '时间' },
    ]);
    revocations.forEach(function (record) {
      const rev = record && typeof record === 'object' ? record : {};
      const tr = el('tr');
      const kindMeta = REVOCATION_KIND_META[rev.kind];
      const kindTone = rev.kind === 'node' ? 'danger' : rev.kind === 'token' ? 'warn' : 'info';
      tr.appendChild(cellNode(badge(kindMeta ? kindMeta.label : textOr(rev.kind), kindTone, textOr(rev.kind))));
      tr.appendChild(cell(textOr(rev.value), 'mono cell-ellipsis', textOr(rev.value)));
      tr.appendChild(cell(textOr(rev.reason), 'cell-ellipsis', textOr(rev.reason)));
      tr.appendChild(cell(fmtTime(pickTimestamp(rev)), 'mono cell-nowrap'));
      built.tbody.appendChild(tr);
    });
    const wrap = el('div', 'table-wrap');
    wrap.appendChild(built.table);
    refs.body.appendChild(wrap);
  }

  async function loadRevocations(loadOptions) {
    const settings = loadOptions || {};
    if (loading || destroyed) return;
    loading = true;
    if (!settings.silent && refs) {
      clear(refs.body);
      refs.body.appendChild(loadingBlock('正在加载吊销列表…'));
    }
    try {
      const data = await api('GET', '/revocations', { signal: ac.signal });
      if (destroyed) return;
      if (!Array.isArray(data)) {
        renderError('吊销列表接口返回格式异常（期望数组）。');
        return;
      }
      revocations = data;
      renderRevocations();
    } catch (err) {
      if (isAborted(err) || destroyed) return;
      renderError(err.message || '吊销列表加载失败。');
    } finally {
      loading = false;
    }
  }

  async function submitRevocation(event) {
    event.preventDefault();
    if (submitting) return;
    clearErrors();

    const kind = refs.kindSelect.value;
    const value = refs.valueInput.value.trim();
    const reason = refs.reasonInput.value.trim();
    const problems = [];
    if (!value) problems.push({ key: 'value', message: '请填写要吊销的值。' });
    if (!reason) problems.push({ key: 'reason', message: '请填写吊销原因。' });
    if (problems.length > 0) {
      problems.forEach(function (problem) {
        setFieldError(problem.key, problem.message);
      });
      return;
    }

    submitting = true;
    refs.submitBtn.disabled = true;
    refs.submitBtn.textContent = '提交中…';
    try {
      await api('POST', '/revocations', {
        body: { kind: kind, value: value, reason: reason },
        signal: ac.signal,
      });
      toast('吊销已提交，节点将在 30 秒内同步生效。', 'success');
      refs.valueInput.value = '';
      refs.reasonInput.value = '';
      await loadRevocations({ silent: true });
    } catch (err) {
      if (isAborted(err)) return;
      const message = err.message || '提交吊销失败。';
      refs.formError.textContent = message;
      refs.formError.classList.remove('hidden');
      if (!err.handled) toast(message, 'error');
    } finally {
      submitting = false;
      refs.submitBtn.disabled = false;
      refs.submitBtn.textContent = '提交吊销';
    }
  }

  return {
    async mount(host) {
      host.appendChild(buildPageHead({
        title: '吊销',
        desc: '对令牌、主体或节点立即吊销授权',
        actions: [
          button('刷新', { onClick: function () { loadRevocations(); } }),
        ],
      }));

      const formPanel = buildPanel('提交吊销', { bodyClass: 'panel__body' });
      formPanel.body.innerHTML = REVOCATION_FORM_HTML; // 静态骨架
      host.appendChild(formPanel.panel);

      const listPanel = buildPanel('当前吊销列表', { bodyClass: 'panel__body panel__body--flush' });
      const count = el('span', 'panel__meta', '');
      listPanel.head.appendChild(count);
      host.appendChild(listPanel.panel);

      const form = formPanel.body.querySelector('#rev-form');
      refs = {
        form: form,
        kindSelect: form.querySelector('#rev-kind'),
        valueInput: form.querySelector('#rev-value'),
        reasonInput: form.querySelector('#rev-reason'),
        submitBtn: form.querySelector('#rev-submit'),
        formError: form.querySelector('#rev-form-error'),
        kindHint: form.querySelector('#rev-kind-hint'),
        body: listPanel.body,
        count: count,
      };

      form.addEventListener('submit', submitRevocation);
      refs.kindSelect.addEventListener('change', updateKindHint);
      updateKindHint();
      await loadRevocations();
    },
    destroy() {
      destroyed = true;
      ac.abort();
    },
  };
}

/* --------------------------------------------------------------------------
 * 404
 * ------------------------------------------------------------------------ */

function notFoundView() {
  return {
    async mount(host) {
      host.appendChild(buildPageHead({
        title: '页面不存在',
        desc: '请检查地址，或从左侧导航进入功能页面。',
        actions: [
          button('返回总览', {
            variant: 'primary',
            onClick: function () {
              setHash('#/overview');
            },
          }),
        ],
      }));
      const panelRef = buildPanel('未找到页面', { bodyClass: 'panel__body' });
      panelRef.body.appendChild(emptyBlock('没有找到该页面', '当前地址无效。'));
      host.appendChild(panelRef.panel);
    },
    destroy() {},
  };
}

/* --------------------------------------------------------------------------
 * 启动
 * ------------------------------------------------------------------------ */

function onUnhandledRejection(event) {
  const reason = event && event.reason;
  if (!reason || isAborted(reason) || reason.handled) return;
  toast(reason.message || '发生未知错误。', 'error');
}

async function boot() {
  initTheme();
  window.addEventListener('hashchange', function () {
    handleRoute().catch(onRouteError);
  });
  window.addEventListener('unhandledrejection', onUnhandledRejection);

  await detectSession();
  if (!location.hash) {
    location.hash = '#/overview';
  } else {
    handleRoute().catch(onRouteError);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
