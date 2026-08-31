/* Wazuh 规则依赖可视化 - 前端主逻辑
 * 交互模型：文件夹式钻取
 *   首页(分组列表,分页) → 分组详情(规则列表,分页) → 规则详情(上游依赖树,可折叠)
 *   面包屑导航随时返回；图谱保留为辅助视图
 */
const API_BASE = '';

const state = {
    view: 'overview',          // overview | group | rule | graph
    breadcrumb: [],             // [{type:'group'|'rule', name?, id?}]
    overview: null,
    overviewPage: 1,
    overviewPageSize: 24,
    groupPage: 1,
    groupPageSize: 20,
    groupSearch: '',
    currentGroup: null,
    currentRule: null,
    graphData: null,
    selectedNodeId: null,
    selectedType: null,
    simulation: null,
    searchTimer: null,
    treeBound: false,
};

/* ============ 工具 ============ */
function $(id) { return document.getElementById(id); }

async function api(path, options) {
    const resp = await fetch(`${API_BASE}${path}`, options);
    let data = null;
    try { data = await resp.json(); } catch { /* ignore */ }
    if (!resp.ok) {
        const msg = (data && data.error) ? data.error : `HTTP ${resp.status}`;
        const err = new Error(msg);
        err.status = resp.status;
        throw err;
    }
    return data;
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
}

function edgeStyle(type) {
    switch (type) {
        case 'if_sid':           return { color: '#f0883e', marker: 'url(#arrowR)', width: 2.0, dash: null };
        case 'if_group':         return { color: '#3fb950', marker: 'url(#arrowG)', width: 1.8, dash: null };
        case 'if_matched_group': return { color: '#58a6ff', marker: 'url(#arrowB)', width: 1.8, dash: '4 2' };
        case 'member':           return { color: '#6e7681', marker: 'url(#arrowM)', width: 1.2, dash: '2 2' };
        default:                 return { color: '#6e7681', marker: null, width: 1.2, dash: null };
    }
}

function levelColor(level) {
    if (level == null) return '#d0d0d0';
    if (level >= 12) return '#f85149';
    if (level >= 8)  return '#d29922';
    if (level >= 5)  return '#58a6ff';
    return '#3fb950';
}

function levelBadgeColor(level) {
    if (level >= 12) return '#f85149';
    if (level >= 8)  return '#d29922';
    if (level >= 5)  return '#58a6ff';
    return '#3fb950';
}

/* ============ 初始化 ============ */
document.addEventListener('DOMContentLoaded', () => {
    setupEvents();
    checkStatus();
    loadOverview();
});

function setupEvents() {
    $('update-btn').addEventListener('click', updateData);
    $('search-input').addEventListener('input', () => {
        clearTimeout(state.searchTimer);
        state.searchTimer = setTimeout(doSearch, 350);
    });
    $('search-input').addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });

    // 日志定位（独立于搜索）
    $('logtest-btn').addEventListener('click', runLogtest);
    $('logtest-input').addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); runLogtest(); }
    });

    $('show-member').addEventListener('change', () => { if (state.graphData) renderGraphSVG(state.graphData); });
    $('clear-view-btn').addEventListener('click', () => {
        // 从图谱返回：回到之前的规则详情或首页
        if (state.currentRule) goRule(state.currentRule);
        else goOverview();
    });
    $('rule-graph-btn').addEventListener('click', () => {
        if (state.currentRule) showGraphForRule(state.currentRule);
    });
    $('group-graph-btn').addEventListener('click', () => {
        if (state.currentGroup) showGraphForGroup(state.currentGroup);
    });

    // 首页分组搜索
    $('overview-search').addEventListener('input', () => {
        state.overviewPage = 1;
        renderOverview();
    });
    // 分组详情规则搜索（防抖）
    let groupSearchTimer = null;
    $('group-search').addEventListener('input', () => {
        clearTimeout(groupSearchTimer);
        groupSearchTimer = setTimeout(() => {
            state.groupSearch = $('group-search').value.trim();
            state.groupPage = 1;
            renderGroupDetail();
        }, 300);
    });

    // XML 模态框
    $('xml-modal-close').addEventListener('click', closeXmlModal);
    $('xml-modal').addEventListener('click', (e) => {
        if (e.target.id === 'xml-modal') closeXmlModal();
    });
    $('xml-copy-path').addEventListener('click', () => {
        const path = $('xml-file-path').textContent;
        if (path && path !== '-' && path !== '加载中...') {
            navigator.clipboard.writeText(path).then(() => {
                $('xml-copy-path').textContent = '已复制!';
                setTimeout(() => $('xml-copy-path').textContent = '复制路径', 1500);
            });
        }
    });
    // 标签切换
    document.querySelectorAll('.xml-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.xml-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            xmlModalState.tab = tab.dataset.tab;
            loadXmlContent();
        });
    });
    // 刷新文件缓存
    $('xml-refresh-btn').addEventListener('click', async () => {
        if (!xmlModalState.ruleId) return;
        const btn = $('xml-refresh-btn');
        btn.disabled = true; btn.textContent = '⏳ 刷新中...';
        try {
            const data = await api(`/api/rule/${xmlModalState.ruleId}/file/refresh`, { method: 'POST' });
            if (!data.success) throw new Error(data.error);
            await loadXmlContent();
        } catch (e) {
            alert('刷新失败: ' + e.message);
        } finally {
            btn.disabled = false; btn.textContent = '🔄 刷新文件';
        }
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !$('xml-modal').classList.contains('hidden')) {
            closeXmlModal();
        }
    });

    window.addEventListener('resize', () => {
        if (state.simulation && state.view === 'graph') {
            const w = $('content').clientWidth, h = $('content').clientHeight;
            d3.select('#graph-svg').attr('width', w).attr('height', h);
            state.simulation.force('center', d3.forceCenter(w / 2, h / 2));
            state.simulation.alpha(0.3).restart();
        }
    });
}

/* ============ 连接状态 ============ */
async function checkStatus() {
    const dot = $('status-dot'), text = $('status-text');
    dot.className = 'dot yellow'; text.textContent = '检测中...';
    try {
        const data = await api('/api/status');
        if (data.status === 'ok') { dot.className = 'dot green'; text.textContent = '已连接'; }
        else { dot.className = 'dot red'; text.textContent = '连接失败'; }
    } catch { dot.className = 'dot red'; text.textContent = '后端未运行'; }
}

/* ============ 视图路由 / 面包屑 ============ */
function goOverview() {
    state.view = 'overview';
    state.breadcrumb = [];
    state.overviewPage = 1;
    renderView();
}

function goGroup(name) {
    state.view = 'group';
    state.currentGroup = name;
    state.groupPage = 1;
    state.groupSearch = '';
    if ($('group-search')) $('group-search').value = '';
    state.breadcrumb = [{ type: 'group', name }];
    renderView();
}

function goRule(id, fromGroup) {
    state.view = 'rule';
    state.currentRule = String(id);
    state.selectedNodeId = String(id);
    state.selectedType = 'rule';
    if (fromGroup) {
        state.breadcrumb = [{ type: 'group', name: fromGroup }, { type: 'rule', id: String(id) }];
    } else {
        // 从搜索/树进入：如果当前面包屑末尾是 rule，替换它；否则新建
        if (state.breadcrumb.length && state.breadcrumb[state.breadcrumb.length - 1].type === 'rule') {
            state.breadcrumb[state.breadcrumb.length - 1] = { type: 'rule', id: String(id) };
        } else {
            state.breadcrumb = [{ type: 'rule', id: String(id) }];
        }
    }
    renderView();
}

function renderView() {
    ['overview-view', 'group-view', 'rule-view', 'graph-view'].forEach(id => $(id).classList.add('hidden'));
    renderBreadcrumb();
    if (state.view === 'overview') { $('overview-view').classList.remove('hidden'); renderOverview(); }
    else if (state.view === 'group') { $('group-view').classList.remove('hidden'); renderGroupDetail(); }
    else if (state.view === 'rule') { $('rule-view').classList.remove('hidden'); renderRuleDetail(); }
    else if (state.view === 'graph') { $('graph-view').classList.remove('hidden'); }
}

function renderBreadcrumb() {
    const bc = $('breadcrumb');
    let html = `<span class="bc-item" data-nav="overview">🏠 首页</span>`;
    state.breadcrumb.forEach(item => {
        html += `<span class="bc-sep">/</span>`;
        if (item.type === 'group') {
            html += `<span class="bc-item" data-nav="group" data-name="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>`;
        } else {
            html += `<span class="bc-item bc-current">#${escapeHtml(item.id)}</span>`;
        }
    });
    bc.innerHTML = html;
    bc.querySelectorAll('.bc-item[data-nav]').forEach(el => {
        el.addEventListener('click', () => {
            if (el.dataset.nav === 'overview') goOverview();
            else if (el.dataset.nav === 'group') goGroup(el.dataset.name);
        });
    });
}

/* ============ 分页器（含跳转指定页） ============ */
function renderPager(containerId, current, totalPages, onChange) {
    const el = $(containerId);
    if (totalPages <= 1) { el.innerHTML = ''; return; }
    let html = '';
    if (current > 1) html += `<button class="btn btn-ghost btn-xs" data-page="${current - 1}">‹ 上一页</button>`;
    html += `<span class="pager-info">第 ${current} / ${totalPages} 页</span>`;
    html += `<span class="pager-jump">跳至 <input type="number" min="1" max="${totalPages}" value="${current}" data-jump-input> 页 <button class="btn btn-ghost btn-xs" data-jump-go>GO</button></span>`;
    if (current < totalPages) html += `<button class="btn btn-ghost btn-xs" data-page="${current + 1}">下一页 ›</button>`;
    el.innerHTML = html;
    el.querySelectorAll('button[data-page]').forEach(b => {
        b.addEventListener('click', () => onChange(parseInt(b.dataset.page)));
    });
    const input = el.querySelector('[data-jump-input]');
    const goBtn = el.querySelector('[data-jump-go]');
    const doJump = () => {
        const v = parseInt(input.value);
        if (!isNaN(v) && v >= 1 && v <= totalPages) onChange(v);
        else input.value = current;
    };
    goBtn.addEventListener('click', doJump);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') doJump(); });
}

/* ============ 首页：分组列表（分页） ============ */
async function loadOverview() {
    $('load-message').textContent = '加载中...';
    try {
        const data = await api('/api/overview');
        if (!data.success) throw new Error(data.error);
        state.overview = data.data;
        $('total-rules').textContent = data.data.total_rules;
        $('group-count').textContent = data.data.group_count;
        $('cache-detail').textContent = data.data.cache?.updated_at || '无缓存';
        $('cache-time').textContent = '缓存：' + (data.data.cache?.updated_at || '-');
        $('load-message').textContent = '数据已加载，点击分组查看规则';
        renderView();
    } catch (e) {
        $('load-message').textContent = '加载失败：' + e.message;
        if (String(e.status) === '500') {
            $('load-message').textContent += '（请检查 .env 中 WAZUH_HOST 配置后，点右上角"更新数据"）';
        }
    }
}

function renderOverview() {
    if (!state.overview) return;
    const allGroups = state.overview.groups;
    // 分组名搜索过滤
    const kw = ($('overview-search')?.value || '').trim().toLowerCase();
    const groups = kw ? allGroups.filter(g => g.name.toLowerCase().includes(kw)) : allGroups;
    const total = groups.length;
    const pages = Math.ceil(total / state.overviewPageSize) || 1;
    state.overviewPage = Math.min(Math.max(1, state.overviewPage), pages);
    $('overview-meta').textContent = kw ? `匹配 ${total} / ${allGroups.length} 个分组` : `共 ${total} 个分组`;
    const start = (state.overviewPage - 1) * state.overviewPageSize;
    const pageItems = groups.slice(start, start + state.overviewPageSize);
    if (!pageItems.length) {
        $('group-grid').innerHTML = '<p class="muted" style="grid-column:1/-1;padding:20px">没有匹配的分组</p>';
    } else {
        $('group-grid').innerHTML = pageItems.map(g => `
        <div class="group-card" data-group="${escapeHtml(g.name)}">
            <span class="gc-level" style="background:${levelBadgeColor(g.max_level)}">L${g.max_level}</span>
            <div class="gc-name">${escapeHtml(g.name)}</div>
            <div class="gc-count">${g.count}</div>
            <div class="gc-count-label">条规则</div>
        </div>`).join('');
        $('group-grid').querySelectorAll('.group-card').forEach(el => {
            el.addEventListener('click', () => goGroup(el.dataset.group));
        });
    }
    renderPager('overview-pager', state.overviewPage, pages, (p) => {
        state.overviewPage = p; renderOverview();
    });
}

/* ============ 分组详情：规则列表（分页） ============ */
async function renderGroupDetail() {
    const name = state.currentGroup;
    $('group-title').textContent = `[组] ${name}`;
    $('group-rule-list').innerHTML = '<p class="muted">加载中...</p>';
    $('group-pager').innerHTML = '';
    try {
        const offset = (state.groupPage - 1) * state.groupPageSize;
        let url = `/api/rules?group=${encodeURIComponent(name)}&limit=${state.groupPageSize}&offset=${offset}`;
        if (state.groupSearch) url += `&q=${encodeURIComponent(state.groupSearch)}`;
        const data = await api(url);
        if (!data.success) throw new Error(data.error);
        const { rules, total } = data.data;
        $('group-meta').textContent = state.groupSearch
            ? `匹配 ${total} 条（关键词：${state.groupSearch}）`
            : `共 ${total} 条规则`;
        if (!rules.length) {
            $('group-rule-list').innerHTML = '<p class="muted" style="padding:20px">没有匹配的规则</p>';
            $('group-pager').innerHTML = '';
            return;
        }
        $('group-rule-list').innerHTML = rules.map(r => {
            const otherGroups = (r.groups || []).filter(g => g !== name).slice(0, 3).join(', ');
            return `
            <div class="rule-row" data-id="${escapeHtml(r.id)}">
                <span class="r-badge" style="background:${levelColor(r.level)}">#${escapeHtml(r.id)}</span>
                <span class="r-level">L${escapeHtml(r.level)}</span>
                <span class="r-desc">${escapeHtml(r.description || '')}</span>
                <span class="r-groups">${escapeHtml(otherGroups)}</span>
            </div>`;
        }).join('');
        $('group-rule-list').querySelectorAll('.rule-row').forEach(el => {
            el.addEventListener('click', () => goRule(el.dataset.id, name));
        });
        const pages = Math.ceil(total / state.groupPageSize) || 1;
        state.groupPage = Math.min(Math.max(1, state.groupPage), pages);
        renderPager('group-pager', state.groupPage, pages, (p) => {
            state.groupPage = p; renderGroupDetail();
        });
    } catch (e) {
        $('group-rule-list').innerHTML = `<p class="muted">加载失败：${escapeHtml(e.message)}</p>`;
    }
}

/* ============ 规则详情：基本信息 + 上游依赖树 ============ */
async function renderRuleDetail() {
    const id = state.currentRule;
    $('rule-title').textContent = `规则 #${id}`;
    $('rule-info-card').innerHTML = '<p class="muted">加载中...</p>';
    $('rule-tree').innerHTML = '';
    try {
        const data = await api(`/api/rule/${id}`);
        if (!data.success) throw new Error(data.error);
        const r = data.data;
        $('rule-info-card').innerHTML = renderRuleCard(r) +
            `<div class="rule-actions"><button id="view-xml-btn" class="btn btn-ghost btn-xs">📄 查看 XML 定义 / 文件位置</button></div>`;
        const xmlBtn = $('view-xml-btn');
        if (xmlBtn) xmlBtn.addEventListener('click', () => openXmlModal(id));
        showRuleDetail(id);
        loadRuleTree(id);
    } catch (e) {
        $('rule-info-card').innerHTML = `<p class="muted">加载失败：${escapeHtml(e.message)}</p>`;
    }
}

function renderRuleCard(r) {
    const groups = Array.isArray(r.groups) ? r.groups.join(', ') : (r.groups || 'N/A');
    let html = `
        <div class="detail-item"><span class="label">ID:</span> <span class="value">#${escapeHtml(r.id)}</span></div>
        <div class="detail-item"><span class="label">级别:</span> <span class="value">${escapeHtml(r.level ?? 'N/A')}</span></div>
        <div class="detail-item"><span class="label">描述:</span> <span class="value">${escapeHtml(r.description || 'N/A')}</span></div>
        <div class="detail-item"><span class="label">分组:</span> <span class="value">${escapeHtml(groups)}</span></div>
        <div class="detail-item"><span class="label">文件:</span> <span class="value">${escapeHtml(r.file || 'N/A')}</span></div>`;
    const deps = [];
    if (r.if_sid && r.if_sid.length) deps.push(`if_sid → ${r.if_sid.map(x => '#' + x).join(', ')}`);
    if (r.if_group && r.if_group.length) deps.push(`if_group → ${r.if_group.join(', ')}`);
    if (r.if_matched_group && r.if_matched_group.length) deps.push(`if_matched_group → ${r.if_matched_group.join(', ')}`);
    if (deps.length) html += `<div class="detail-item"><span class="label">依赖条件:</span> <span class="value">${deps.join('<br>')}</span></div>`;
    return html;
}

async function showRuleDetail(ruleId) {
    const detail = $('rule-detail');
    detail.innerHTML = '<p class="muted">加载中...</p>';
    try {
        const data = await api(`/api/rule/${ruleId}`);
        if (data.success) detail.innerHTML = renderRuleCard(data.data);
    } catch (e) {
        detail.innerHTML = `<p class="muted">获取详情失败：${escapeHtml(e.message)}</p>`;
    }
}

/* ============ 依赖树（懒加载，可折叠） ============ */
async function loadRuleTree(ruleId) {
    const container = $('rule-tree');
    container.innerHTML = '<p class="muted">加载中...</p>';
    bindTreeContainer();
    try {
        const data = await api(`/api/chain/rule/${ruleId}`);
        if (!data.success) throw new Error(data.error);
        const { node, children } = data.data;
        const rootHtml = renderTreeNode(node);
        const kidsHtml = children.length
            ? children.map(c => renderTreeNode(c)).join('')
            : '<div class="t-leaf muted">该规则没有上游依赖（无 if_sid / if_group / if_matched_group）</div>';
        container.innerHTML = rootHtml.replace(
            '<div class="t-children" data-children></div>',
            `<div class="t-children" data-children>${kidsHtml}</div>`
        );
        const toggle = container.querySelector(`.t-node[data-id="${ruleId}"] .t-toggle`);
        if (toggle) { toggle.textContent = '▾'; toggle.dataset.open = '1'; }
    } catch (e) {
        container.innerHTML = `<p class="muted">加载失败：${escapeHtml(e.message)}</p>`;
    }
}

function renderTreeNode(node) {
    if (node.type === 'group') {
        const cnt = node.count != null ? `<span class="t-count">${node.count} 条</span>` : '';
        const kindTag = node.kind === 'if_group'
            ? '<span class="t-tag t-ifgroup">if_group</span>'
            : (node.kind === 'if_matched_group' ? '<span class="t-tag t-ifmg">if_matched_group</span>' : '');
        return `<div class="t-node t-group" data-type="group" data-name="${escapeHtml(node.name)}">
            <div class="t-row">
                <span class="t-toggle" data-action="toggle">▸</span>
                <span class="t-badge t-group-badge">[组] ${escapeHtml(node.name)}</span>
                ${cnt}${kindTag}
            </div>
            <div class="t-children" data-children></div>
        </div>`;
    }
    const color = levelColor(node.level);
    const kindTag = node.kind === 'root'
        ? '<span class="t-tag t-root">当前规则</span>'
        : (node.kind === 'if_sid' ? '<span class="t-tag t-ifsid">if_sid</span>'
            : (node.kind === 'member' ? '<span class="t-tag t-member">组内</span>' : ''));
    const missTag = node.missing ? '<span class="t-tag t-warn">未缓存</span>' : '';
    const desc = node.description ? `<span class="t-desc">${escapeHtml(node.description)}</span>` : '';
    return `<div class="t-node t-rule" data-type="rule" data-id="${escapeHtml(node.id)}">
        <div class="t-row">
            <span class="t-toggle" data-action="toggle">▸</span>
            <span class="t-badge" style="background:${color}">#${escapeHtml(node.id)}</span>
            <span class="t-level">L${escapeHtml(node.level ?? '?')}</span>
            ${kindTag}${missTag}
            ${desc}
        </div>
        <div class="t-children" data-children></div>
    </div>`;
}

function bindTreeContainer() {
    if (state.treeBound) return;
    state.treeBound = true;
    document.addEventListener('click', async (e) => {
        if (!e.target.closest('#rule-tree')) return;
        const row = e.target.closest('.t-row');
        if (!row) return;
        const el = row.parentElement;
        const type = el.dataset.type;
        const toggle = row.querySelector('.t-toggle');
        const kids = el.querySelector('[data-children]');

        // "查看全部"链接
        const viewAll = e.target.closest('[data-action="view-all-group"]');
        if (viewAll) { goGroup(viewAll.dataset.name); return; }

        // 点节点主体 → 跳转
        if (!e.target.closest('[data-action="toggle"]')) {
            if (type === 'rule') goRule(el.dataset.id);
            else if (type === 'group') goGroup(el.dataset.name);
            return;
        }

        // 折叠
        if (toggle.dataset.open === '1') {
            toggle.dataset.open = '0'; toggle.textContent = '▸'; kids.innerHTML = '';
            return;
        }

        // 展开（懒加载）
        toggle.dataset.open = '1'; toggle.textContent = '…';
        try {
            let data;
            if (type === 'rule') data = await api(`/api/chain/rule/${el.dataset.id}`);
            else data = await api(`/api/chain/group/${encodeURIComponent(el.dataset.name)}`);
            const children = data.data.children || [];
            if (!children.length) {
                toggle.dataset.open = '0'; toggle.textContent = '·';
                kids.innerHTML = '<div class="t-leaf muted">无依赖</div>';
                return;
            }
            toggle.textContent = '▾';
            if (type === 'group') {
                // 分组只显示前 10 条 + 查看全部链接
                const total = data.data.total || children.length;
                const shown = children.slice(0, 10);
                kids.innerHTML = shown.map(c => renderTreeNode(c)).join('');
                if (total > 10) {
                    kids.insertAdjacentHTML('beforeend',
                        `<div class="t-leaf"><a class="t-view-all" data-action="view-all-group" data-name="${escapeHtml(el.dataset.name)}">查看全部 ${total} 条 →</a></div>`);
                }
            } else {
                kids.innerHTML = children.map(c => renderTreeNode(c)).join('');
            }
        } catch (err) {
            toggle.dataset.open = '0'; toggle.textContent = '▸';
            kids.innerHTML = `<div class="t-leaf muted">加载失败：${escapeHtml(err.message)}</div>`;
        }
    });
}

/* ============ 统一搜索（智能识别：规则ID / 关键词 / 告警JSON / 日志） ============ */
async function doSearch() {
    const q = $('search-input').value.trim();
    const results = $('search-results');
    const meta = $('search-meta');
    if (!q) { results.innerHTML = ''; meta.textContent = ''; return; }

    // 1) 纯数字 → 直接进规则详情
    if (/^\d+$/.test(q)) {
        meta.textContent = `规则 #${q}`;
        results.innerHTML = '';
        goRule(q);
        return;
    }

    // 2) 告警 JSON → 提取 rule.id
    if (q.startsWith('{')) {
        try {
            const obj = JSON.parse(q);
            const r = obj.rule;
            let rid = null;
            if (typeof r === 'object' && r !== null) rid = r.id ?? r.rule_id;
            else if (typeof r === 'number') rid = r;
            if (rid) {
                meta.textContent = `告警命中规则 #${rid}`;
                results.innerHTML = '';
                goRule(rid);
                return;
            }
        } catch { /* 不是合法 JSON，继续关键词搜索 */ }
        meta.textContent = 'JSON 中未找到 rule.id，按关键词搜索';
    }

    // 3) 关键词搜索
    meta.textContent = '搜索中...';
    try {
        const data = await api(`/api/rules?q=${encodeURIComponent(q)}&limit=20`);
        if (!data.success) throw new Error(data.error);
        const { rules, total } = data.data;
        if (!rules.length) {
            meta.textContent = `命中 0 条`;
            results.innerHTML = '<div class="result-empty">未找到匹配规则，可试试下方「🧪 日志定位」</div>';
            return;
        }
        meta.textContent = `命中 ${total} 条（显示前 ${rules.length} 条）`;
        results.innerHTML = rules.map(r => `
            <div class="result-item" data-id="${escapeHtml(r.id)}">
                <span class="r-id">#${escapeHtml(r.id)}</span>
                <span class="r-level">L${escapeHtml(r.level)}</span>
                <span class="r-desc">${escapeHtml(r.description || '')}</span>
            </div>`).join('');
        results.querySelectorAll('.result-item').forEach(el => {
            el.addEventListener('click', () => goRule(el.dataset.id));
        });
    } catch (e) {
        meta.textContent = '搜索失败：' + e.message;
    }
}

/* ============ 日志定位（logtest，独立于搜索） ============ */
async function runLogtest() {
    const log = $('logtest-input').value.trim();
    const box = $('logtest-result');
    if (!log) { box.innerHTML = '<p class="muted">请先粘贴一条日志</p>'; return; }
    const btn = $('logtest-btn');
    btn.disabled = true; btn.textContent = '⏳ 测试中...';
    box.innerHTML = '<p class="muted">正在测试命中...（需 Wazuh 在线）</p>';
    try {
        const data = await api('/api/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log }),
        });
        if (!data.success) throw new Error(data.error);
        const rule = data.data?.output?.rule || data.data?.matched_rule || data.data?.rule;
        if (!rule?.id) {
            box.innerHTML = '<p class="muted">未命中任何规则</p>';
            return;
        }
        box.innerHTML = `
            <div class="lt-hit">
                <p class="lt-title">命中规则 #${escapeHtml(rule.id)}　L${escapeHtml(rule.level)}</p>
                <p class="muted">${escapeHtml(rule.description || '')}</p>
                <p class="muted sub">分组：${escapeHtml((rule.groups || []).join(', ') || '-')}</p>
                <button class="btn btn-ghost btn-xs" id="lt-goto">查看规则详情 / 依赖链</button>
            </div>`;
        $('lt-goto').addEventListener('click', () => goRule(rule.id));
    } catch (e) {
        box.innerHTML = `<p class="muted">测试失败：${escapeHtml(e.message)}</p>`;
    } finally {
        btn.disabled = false; btn.textContent = '测试命中规则';
    }
}

/* ============ 图谱视图（辅助） ============ */
function showGraphForRule(ruleId) {
    state.view = 'graph';
    renderView();
    loadGraph(`/api/graph?rule_id=${ruleId}&depth=1`, `规则 #${ruleId} 依赖图谱`);
}

function showGraphForGroup(name) {
    state.view = 'graph';
    renderView();
    loadGraph(`/api/graph?groups=${encodeURIComponent(name)}`, `分组 [${name}] 依赖图谱`);
}

function showLoading(text) {
    $('loading-text').textContent = text || '加载中...';
    $('loading-mask').classList.remove('hidden');
}
function hideLoading() { $('loading-mask').classList.add('hidden'); }

async function loadGraph(path, desc) {
    showLoading('加载图谱...');
    try {
        const data = await api(path);
        if (!data.success) throw new Error(data.error);
        state.graphData = data.data;
        $('graph-desc').textContent = data.data.message || desc || '';
        renderGraphSVG(data.data);
    } catch (e) {
        alert('图谱加载失败：' + e.message);
    } finally {
        hideLoading();
    }
}

function renderGraphSVG(data) {
    const width = $('content').clientWidth;
    const height = $('content').clientHeight;
    const svg = d3.select('#graph-svg').attr('width', width).attr('height', height);
    svg.selectAll('g.layer').remove();
    $('graph-empty').classList.add('hidden');

    if (!data.nodes.length) {
        $('graph-empty').classList.remove('hidden');
        state.simulation = null;
        return;
    }

    const showMember = $('show-member').checked;
    const edges = data.edges.filter(e => showMember || e.type !== 'member');

    const g = svg.append('g').attr('class', 'layer');
    const simulation = d3.forceSimulation(data.nodes)
        .force('link', d3.forceLink(edges).id(d => d.id)
            .distance(d => (d.type === 'if_sid' ? 130 : 100)).strength(0.5))
        .force('charge', d3.forceManyBody().strength(-320))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide().radius(d => (d.type === 'group' ? 34 : 26)))
        .force('x', d3.forceX(width / 2).strength(0.04))
        .force('y', d3.forceY(height / 2).strength(0.04));
    state.simulation = simulation;

    const link = g.append('g').selectAll('line').data(edges).enter().append('line')
        .attr('stroke', d => edgeStyle(d.type).color)
        .attr('stroke-width', d => edgeStyle(d.type).width)
        .attr('stroke-opacity', 0.75)
        .attr('stroke-dasharray', d => edgeStyle(d.type).dash)
        .attr('marker-end', d => edgeStyle(d.type).marker);

    const node = g.append('g').selectAll('g').data(data.nodes).enter().append('g')
        .attr('cursor', 'pointer')
        .call(d3.drag().on('start', dragstart).on('drag', dragging).on('end', dragend))
        .on('click', (event, d) => {
            if (d.type === 'rule') goRule(d.id);
        });

    node.each(function (d) {
        const el = d3.select(this);
        if (d.type === 'group') {
            el.append('rect').attr('x', -34).attr('y', -12).attr('width', 68).attr('height', 24)
                .attr('rx', 6).attr('fill', '#8957e5').attr('fill-opacity', 0.25)
                .attr('stroke', '#8957e5').attr('stroke-width', 1.5);
        } else if (d.missing) {
            el.append('circle').attr('r', 10).attr('fill', '#1c2128')
                .attr('stroke', '#8b949e').attr('stroke-width', 1.5).attr('stroke-dasharray', '3 2');
        } else {
            el.append('circle').attr('r', d => 8 + Math.min((d.level || 0) / 2, 12))
                .attr('fill', d => levelColor(d.level)).attr('fill-opacity', 0.85)
                .attr('stroke', '#0d1117').attr('stroke-width', 2);
        }
    });

    node.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', d => (d.type === 'group' ? 4 : -20))
        .attr('font-size', d => (d.type === 'group' ? 11 : 10))
        .attr('font-weight', d => (d.type === 'group' ? 600 : 400))
        .attr('fill', d => (d.type === 'group' ? '#d2a8ff' : '#8b949e'))
        .text(d => d.label)
        .style('pointer-events', 'none');

    node.on('mouseenter', function (event, d) { showTooltip(event, d); })
        .on('mousemove', e => moveTooltip(e))
        .on('mouseleave', hideTooltip);

    simulation.on('tick', () => {
        link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
        node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    const zoom = d3.zoom().scaleExtent([0.2, 4]).on('zoom', event => {
        g.attr('transform', event.transform);
    });
    svg.call(zoom);

    function dragstart(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
    }
    function dragging(event, d) { d.fx = event.x; d.fy = event.y; }
    function dragend(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
    }
}

/* ============ Tooltip ============ */
function showTooltip(event, d) {
    const tip = $('tooltip');
    let html = '';
    if (d.type === 'group') {
        html = `<div class="title">分组：${escapeHtml(d.name || d.id)}</div>
                <div class="sub">点击查看组内规则</div>`;
    } else if (d.missing) {
        html = `<div class="title">规则 #${escapeHtml(d.id)}</div>
                <div class="sub">${escapeHtml(d.description)}</div>`;
    } else {
        html = `<div class="title">规则 #${escapeHtml(d.id)} · Level ${escapeHtml(d.level)}</div>
                <div class="sub">${escapeHtml(d.description || '无描述')}</div>`;
    }
    tip.innerHTML = html;
    tip.style.display = 'block';
    moveTooltip(event);
}
function moveTooltip(event) {
    const tip = $('tooltip');
    if (tip.style.display !== 'none') {
        tip.style.left = (event.pageX + 14) + 'px';
        tip.style.top = (event.pageY + 6) + 'px';
    }
}
function hideTooltip() { $('tooltip').style.display = 'none'; }

/* ============ 更新数据 ============ */
async function updateData() {
    if (!confirm('将从 Wazuh 重新拉取全部规则并覆盖本地缓存，可能需要数十秒。确定继续？')) return;
    $('update-btn').disabled = true;
    $('update-btn').textContent = '⏳ 更新中...';
    try {
        const data = await api('/api/update', { method: 'POST' });
        if (!data.success) throw new Error(data.error);
        alert(data.message);
        state.overview = data.data;
        $('total-rules').textContent = data.data.total_rules;
        $('group-count').textContent = data.data.group_count;
        $('cache-detail').textContent = data.data.cache?.updated_at || '无缓存';
        $('cache-time').textContent = '缓存：' + (data.data.cache?.updated_at || '-');
        goOverview();
    } catch (e) {
        alert('更新失败：' + e.message);
    } finally {
        $('update-btn').disabled = false;
        $('update-btn').textContent = '🔄 更新数据';
    }
}

/* ============ XML 定义模态框 ============ */
const xmlModalState = { ruleId: null, tab: 'rule' };

async function openXmlModal(ruleId) {
    xmlModalState.ruleId = ruleId;
    xmlModalState.tab = 'rule';
    document.querySelectorAll('.xml-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.tab === 'rule');
    });
    const modal = $('xml-modal');
    modal.classList.remove('hidden');
    $('xml-modal-title').textContent = `规则 #${ruleId} 的 XML 定义`;
    $('xml-file-path').textContent = '加载中...';
    $('xml-cache-info').textContent = '';
    $('xml-content').textContent = '加载中...';
    await loadXmlContent();
}

async function loadXmlContent() {
    const id = xmlModalState.ruleId;
    if (!id) return;
    $('xml-content').textContent = '加载中...';
    try {
        const endpoint = xmlModalState.tab === 'file'
            ? `/api/rule/${id}/file`
            : `/api/rule/${id}/xml`;
        const data = await api(endpoint);
        if (!data.success) throw new Error(data.error);
        $('xml-file-path').textContent = data.data.file_path || '-';
        const cacheTag = data.data.from_cache ? '本地缓存' : '刚从 Wazuh 拉取';
        $('xml-cache-info').textContent = data.data.cached_at
            ? `（${cacheTag} · ${data.data.cached_at}）`
            : `（${cacheTag}）`;
        const xml = xmlModalState.tab === 'file' ? data.data.full_xml : data.data.rule_xml;
        $('xml-content').textContent = xml || '未找到内容';
    } catch (e) {
        $('xml-content').textContent = '加载失败: ' + e.message;
    }
}

function closeXmlModal() {
    $('xml-modal').classList.add('hidden');
}
