"""后端 API 路由。

数据流设计：
- 首次访问自动全量拉取 Wazuh 规则 -> 解析 -> 写入本地缓存 data/rules_cache.json
- 之后所有读接口优先读本地缓存（秒开），不重复请求 Wazuh
- 用户点"更新数据" -> POST /api/update 重新全量拉取并覆盖缓存
- 图谱按"分组 / 关键词 / 规则ID"返回受控子图，避免全量渲染卡顿
"""
from flask import Blueprint, jsonify, request

import json
import os
from datetime import datetime

from app.api.wazuh_client import WazuhClient
from app.core.cache import load_cache, save_cache, cache_info
from app.core.graph_builder import GraphBuilder
from app.core.rule_parser import RuleParser
from config import Config

api_bp = Blueprint('api', __name__)
wazuh = WazuhClient()

# 图谱单次渲染的规则节点上限（超过则提示细化）
MAX_GRAPH_NODES = 400

# 规则文件 XML 缓存目录
RULE_FILES_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'data', 'rule_files')


# ------------------------------------------------------------------ #
# 内部工具
# ------------------------------------------------------------------ #
def _parse_rule_for_cache(r):
    """原始规则 -> 精简缓存格式（含解析后的依赖）。"""
    p = RuleParser.extract_dependencies(r)
    return {
        'id': p['id'],
        'level': r.get('level', 0),
        'description': r.get('description', ''),
        'file': r.get('file', ''),
        'groups': p['groups'],
        'if_sid': p['if_sid'],
        'if_group': p['if_group'],
        'if_matched_group': p['if_matched_group'],
    }


def _refresh_cache():
    """全量拉取 -> 解析 -> 写本地缓存。失败返回 None。"""
    rules, total = wazuh.get_all_rules()
    if rules is None:
        return None
    parsed = [_parse_rule_for_cache(r) for r in rules]
    return save_cache(parsed)


def _get_rules():
    """优先读本地缓存；无缓存则自动全量拉取并落盘。返回缓存负载或 None。"""
    cache = load_cache()
    if cache is not None:
        return cache
    return _refresh_cache()


def _build_overview(cache):
    """聚合分组大类：名称 / 规则数 / 最大级别。"""
    group_map = {}
    for r in cache['rules']:
        for g in r.get('groups', []):
            gi = group_map.setdefault(g, {'name': g, 'count': 0, 'max_level': 0})
            gi['count'] += 1
            if r.get('level', 0) > gi['max_level']:
                gi['max_level'] = r.get('level', 0)
    groups = sorted(group_map.values(), key=lambda x: (-x['count'], x['name']))
    return {
        'groups': groups,
        'group_count': len(groups),
        'total_rules': cache['total'],
        'updated_at': cache.get('updated_at'),
    }


def _gather_around(cache, centers, depth):
    """
    从中心规则出发，双向展开依赖链（还原"打标签规则 ↔ 依赖该标签规则"的完整链条）。

    上游（本规则依赖什么）：
      - if_sid / if_matched_sid 指向的规则
      - if_group / if_matched_group 指向的分组 -> 该分组内所有"打上标签"的规则
    下游（谁依赖本规则）：
      - 通过 if_sid 指向本规则的规则
      - if_group / if_matched_group 指向"本规则所属分组"的规则
    """
    rules = cache['rules']
    rule_map = {str(r['id']): r for r in rules}
    group_members = {}  # 分组 -> 打上该标签的规则
    group_deps = {}     # 分组 -> 依赖该分组的规则
    deps_index = {}     # 规则 -> 通过 if_sid 依赖它的规则
    for r in rules:
        rid = str(r['id'])
        for g in r.get('groups', []):
            group_members.setdefault(g, set()).add(rid)
        for g in r.get('if_group', []) + r.get('if_matched_group', []):
            group_deps.setdefault(g, set()).add(rid)
        for dep in r.get('if_sid', []):
            deps_index.setdefault(str(dep), set()).add(rid)

    result, frontier = set(centers), set(centers)
    for _ in range(depth):
        nxt = set()
        for rid in frontier:
            info = rule_map.get(rid)
            if not info:
                continue
            # 上游：依赖
            for dep in info.get('if_sid', []):
                d = str(dep)
                if d not in result:
                    result.add(d); nxt.add(d)
            for g in info.get('if_group', []) + info.get('if_matched_group', []):
                for m in group_members.get(g, []):
                    if m not in result:
                        result.add(m); nxt.add(m)
            # 下游：被依赖
            for up in deps_index.get(rid, []):
                if up not in result:
                    result.add(up); nxt.add(up)
            for g in info.get('groups', []):
                for d in group_deps.get(g, []):
                    if d not in result:
                        result.add(d); nxt.add(d)
        frontier = nxt
    return result


def _build_subgraph(cache, ids, desc):
    """由命中规则 ID 集合构建受控子图；超限返回 (None, error)。"""
    rule_map = {str(r['id']): r for r in cache['rules']}
    parsed_sub = {rid: rule_map[rid] for rid in ids if rid in rule_map}
    graph = GraphBuilder.build_graph_from_parsed(parsed_sub)
    rule_nodes = [n for n in graph['nodes'] if n['type'] == 'rule']
    if len(rule_nodes) > MAX_GRAPH_NODES:
        return None, f'当前范围命中 {len(rule_nodes)} 条规则，超过渲染上限 {MAX_GRAPH_NODES}。请选择更小的分组或用关键词细化'
    graph['message'] = f'{desc} · {len(rule_nodes)} 规则节点 / {len(graph["edges"])} 边'
    return graph, None


# ------------------------------------------------------------------ #
# 状态与配置
# ------------------------------------------------------------------ #
@api_bp.route('/api/status', methods=['GET'])
def status():
    info = wazuh.status()
    return jsonify(info)


@api_bp.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({
        'success': True,
        'config': {
            'WAZUH_HOST': Config.WAZUH_HOST,
            'WAZUH_PORT': Config.WAZUH_PORT,
            'WAZUH_USERNAME': Config.WAZUH_USERNAME,
        },
    })


@api_bp.route('/api/config', methods=['POST'])
def set_config():
    payload = request.get_json(silent=True) or {}
    wazuh.update_config(
        host=payload.get('WAZUH_HOST'),
        port=payload.get('WAZUH_PORT'),
        username=payload.get('WAZUH_USERNAME'),
        password=payload.get('WAZUH_PASSWORD'),
    )
    ok = wazuh.authenticate()
    return jsonify({
        'success': ok,
        'error': None if ok else '无法连接到新的 Wazuh 服务器',
    })


# ------------------------------------------------------------------ #
# 总览 / 更新 / 缓存
# ------------------------------------------------------------------ #
@api_bp.route('/api/overview', methods=['GET'])
def overview():
    """首页只展示大类：分组名称 + 规则数 + 最大级别。优先读本地缓存。"""
    cache = _get_rules()
    if cache is None:
        return jsonify({'success': False, 'error': '无法获取规则数据，请检查 Wazuh 连接与凭据'}), 500
    data = _build_overview(cache)
    data['cache'] = cache_info()
    return jsonify({'success': True, 'data': data})


@api_bp.route('/api/update', methods=['POST'])
def update():
    """手动更新：重新全量拉取 Wazuh 规则并覆盖本地缓存。"""
    cache = _refresh_cache()
    if cache is None:
        return jsonify({'success': False, 'error': '更新失败：无法连接 Wazuh 或拉取规则，本地缓存未变动'}), 500
    data = _build_overview(cache)
    data['cache'] = cache_info()
    return jsonify({
        'success': True,
        'message': f'更新完成：共 {cache["total"]} 条规则，已写入本地缓存',
        'data': data,
    })


# ------------------------------------------------------------------ #
# 规则列表 / 详情
# ------------------------------------------------------------------ #
@api_bp.route('/api/rules', methods=['GET'])
def list_rules():
    """按 分组 / 级别 / 关键词 过滤规则列表（用于查询结果展示，非图谱）。"""
    cache = _get_rules()
    if cache is None:
        return jsonify({'success': False, 'error': '无法获取规则数据'}), 500
    group = request.args.get('group', '')
    q = request.args.get('q', '').strip()
    level_min = request.args.get('level_min', type=int)
    level_max = request.args.get('level_max', type=int)
    limit = min(request.args.get('limit', default=200, type=int), 1000)
    offset = request.args.get('offset', default=0, type=int)

    matched = []
    for r in cache['rules']:
        if group and group not in r.get('groups', []):
            continue
        if level_min is not None and r['level'] < level_min:
            continue
        if level_max is not None and r['level'] > level_max:
            continue
        if q:
            hay = f"{r['id']} {r['description']} {' '.join(r.get('groups', []))} {r['file']}".lower()
            if q.lower() not in hay:
                continue
        matched.append(r)
    total = len(matched)
    page = matched[offset:offset + limit]
    return jsonify({
        'success': True,
        'data': {'rules': page, 'total': total, 'offset': offset, 'limit': limit},
    })


@api_bp.route('/api/rule/<int:rule_id>', methods=['GET'])
def get_rule(rule_id):
    """规则详情：优先从本地缓存返回。"""
    cache = _get_rules()
    if cache is None:
        return jsonify({'success': False, 'error': '无法获取规则数据'}), 500
    for r in cache['rules']:
        if str(r['id']) == str(rule_id):
            return jsonify({'success': True, 'data': r})
    return jsonify({'success': False, 'error': '规则不存在'}), 404


# ------------------------------------------------------------------ #
# 规则 XML 定义（从 Wazuh 规则文件提取，带本地缓存）
# ------------------------------------------------------------------ #
def _rule_file_cache_path(filename):
    return os.path.join(RULE_FILES_CACHE_DIR, f'{filename}.json')


def _load_rule_file_cache(filename):
    """读取本地缓存的规则文件内容，不存在返回 None。"""
    path = _rule_file_cache_path(filename)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def _save_rule_file_cache(filename, relative_dirname, content):
    """保存规则文件内容到本地缓存。"""
    os.makedirs(RULE_FILES_CACHE_DIR, exist_ok=True)
    path = _rule_file_cache_path(filename)
    payload = {
        'filename': filename,
        'relative_dirname': relative_dirname,
        'content': content,
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False)
    return payload


def _get_rule_file_content(filename, relative_dirname='', force_refresh=False):
    """获取规则文件内容（JSON 化的 XML）：优先本地缓存，无缓存或强制刷新则从 Wazuh 拉取。"""
    if not force_refresh:
        cached = _load_rule_file_cache(filename)
        if cached:
            return cached['content'], cached.get('updated_at', ''), True
    file_json = wazuh.get_rule_file(filename)
    if file_json is None:
        return None, '', False
    saved = _save_rule_file_cache(filename, relative_dirname, file_json)
    return file_json, saved['updated_at'], False


def _file_json_to_xml(file_json, indent=0):
    """把整个规则文件的 JSON 转回 XML 文本。"""
    lines = []
    for key, value in file_json.items():
        lines.append(_value_to_xml(key, value, indent))
    return '\n'.join(lines)


def _find_rule_in_file(obj, rule_id):
    """在文件 JSON 中递归查找指定 ID 的规则对象。"""
    if isinstance(obj, dict):
        if str(obj.get('@id')) == str(rule_id):
            return obj
        for v in obj.values():
            found = _find_rule_in_file(v, rule_id)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_rule_in_file(item, rule_id)
            if found:
                return found
    return None


def _value_to_xml(tag, value, indent=0):
    """把 JSON 值转成 XML 元素文本。处理属性(@xxx)、文本(#text)、数组、嵌套。"""
    pad = '  ' * indent
    if isinstance(value, str):
        return f'{pad}<{tag}>{value}</{tag}>'
    if isinstance(value, (int, float, bool)):
        return f'{pad}<{tag}>{value}</{tag}>'
    if value is None or value == '':
        return f'{pad}<{tag} />'
    if isinstance(value, list):
        return '\n'.join(_value_to_xml(tag, item, indent) for item in value)
    if isinstance(value, dict):
        attrs = []
        text = ''
        children = []
        for k, v in value.items():
            if k.startswith('@'):
                attrs.append(f'{k[1:]}="{v}"')
            elif k == '#text':
                text = str(v)
            else:
                children.append((k, v))
        attr_str = (' ' + ' '.join(attrs)) if attrs else ''
        if children:
            lines = [f'{pad}<{tag}{attr_str}>']
            for ck, cv in children:
                lines.append(_value_to_xml(ck, cv, indent + 1))
            lines.append(f'{pad}</{tag}>')
            return '\n'.join(lines)
        return f'{pad}<{tag}{attr_str}>{text}</{tag}>'
    return f'{pad}<{tag}>{value}</{tag}>'


def _rule_json_to_xml(rule_obj, indent=0):
    """把单条规则的 JSON 对象转回 <rule>...</rule> XML。"""
    pad = '  ' * indent
    attrs = []
    children = []
    for k, v in rule_obj.items():
        if k.startswith('@'):
            attrs.append(f'{k[1:]}="{v}"')
        else:
            children.append((k, v))
    attr_str = (' ' + ' '.join(attrs)) if attrs else ''
    if not children:
        return f'{pad}<rule{attr_str} />'
    lines = [f'{pad}<rule{attr_str}>']
    for ck, cv in children:
        lines.append(_value_to_xml(ck, cv, indent + 1))
    lines.append(f'{pad}</rule>')
    return '\n'.join(lines)


@api_bp.route('/api/rule/<int:rule_id>/xml', methods=['GET'])
def get_rule_xml(rule_id):
    """获取规则的完整 XML 定义及写入文件位置（优先本地缓存）。"""
    if not wazuh.token:
        wazuh.authenticate()
    rule_info = wazuh.get_rule_by_id(rule_id)
    if not rule_info:
        return jsonify({'success': False, 'error': '规则不存在'}), 404
    filename = rule_info.get('filename')
    relative_dirname = rule_info.get('relative_dirname', '')
    if not filename:
        return jsonify({'success': False, 'error': '该规则没有关联文件'}), 404

    file_json, updated_at, from_cache = _get_rule_file_content(filename, relative_dirname)
    if file_json is None:
        return jsonify({'success': False, 'error': '无法获取规则文件内容'}), 500

    rule_block = _find_rule_in_file(file_json, rule_id)
    rule_xml = _rule_json_to_xml(rule_block) if rule_block else ''
    file_path = f'{relative_dirname}/{filename}' if relative_dirname else filename

    return jsonify({
        'success': True,
        'data': {
            'rule_id': rule_id,
            'filename': filename,
            'relative_dirname': relative_dirname,
            'file_path': file_path,
            'rule_xml': rule_xml,
            'cached_at': updated_at,
            'from_cache': from_cache,
        }
    })


@api_bp.route('/api/rule/<int:rule_id>/file', methods=['GET'])
def get_rule_file_full(rule_id):
    """获取规则所在文件的完整 XML（优先本地缓存）。"""
    if not wazuh.token:
        wazuh.authenticate()
    rule_info = wazuh.get_rule_by_id(rule_id)
    if not rule_info:
        return jsonify({'success': False, 'error': '规则不存在'}), 404
    filename = rule_info.get('filename')
    relative_dirname = rule_info.get('relative_dirname', '')
    if not filename:
        return jsonify({'success': False, 'error': '该规则没有关联文件'}), 404

    file_json, updated_at, from_cache = _get_rule_file_content(filename, relative_dirname)
    if file_json is None:
        return jsonify({'success': False, 'error': '无法获取规则文件内容'}), 500

    full_xml = _file_json_to_xml(file_json)
    file_path = f'{relative_dirname}/{filename}' if relative_dirname else filename

    return jsonify({
        'success': True,
        'data': {
            'rule_id': rule_id,
            'filename': filename,
            'file_path': file_path,
            'full_xml': full_xml,
            'cached_at': updated_at,
            'from_cache': from_cache,
        }
    })


@api_bp.route('/api/rule/<int:rule_id>/file/refresh', methods=['POST'])
def refresh_rule_file(rule_id):
    """强制从 Wazuh 重新拉取该规则所在文件并更新本地缓存。"""
    if not wazuh.token:
        wazuh.authenticate()
    rule_info = wazuh.get_rule_by_id(rule_id)
    if not rule_info:
        return jsonify({'success': False, 'error': '规则不存在'}), 404
    filename = rule_info.get('filename')
    relative_dirname = rule_info.get('relative_dirname', '')
    if not filename:
        return jsonify({'success': False, 'error': '该规则没有关联文件'}), 404

    file_json, updated_at, _ = _get_rule_file_content(filename, relative_dirname, force_refresh=True)
    if file_json is None:
        return jsonify({'success': False, 'error': '无法获取规则文件内容'}), 500

    return jsonify({
        'success': True,
        'message': f'文件 {filename} 已更新',
        'data': {'filename': filename, 'cached_at': updated_at},
    })


# ------------------------------------------------------------------ #
# 依赖树（懒加载：逐层展开，避免一次拉全量）
# ------------------------------------------------------------------ #
def _build_index(cache):
    """构建规则 map / 分组→组内规则 map，供树接口复用。"""
    rule_map = {str(r['id']): r for r in cache['rules']}
    group_members = {}
    for r in cache['rules']:
        for g in r.get('groups', []):
            group_members.setdefault(g, []).append(r)
    return rule_map, group_members


def _rule_node(rule_map, rid, kind='rule'):
    """把一条缓存规则转成树节点（不含 children）。"""
    info = rule_map.get(rid)
    if info is None:
        return {
            'id': rid, 'type': 'rule', 'kind': kind, 'label': f'#{rid}',
            'level': None, 'description': '（规则不在本地缓存中）',
            'groups': [], 'file': '', 'missing': True,
        }
    return {
        'id': str(info['id']), 'type': 'rule', 'kind': kind, 'label': f'#{info["id"]}',
        'level': info.get('level'), 'description': info.get('description', ''),
        'groups': info.get('groups', []), 'file': info.get('file', ''),
        'missing': False,
    }


@api_bp.route('/api/chain/rule/<int:rule_id>', methods=['GET'])
def chain_rule(rule_id):
    """规则的上游依赖：返回该规则节点 + 它依赖的 if_sid 规则 / 分组节点（一层，前端懒加载展开）。"""
    cache = _get_rules()
    if cache is None:
        return jsonify({'success': False, 'error': '无法获取规则数据'}), 500
    rule_map, group_members = _build_index(cache)
    center = str(rule_id)
    if center not in rule_map:
        return jsonify({'success': False, 'error': f'规则 #{rule_id} 不存在'}), 404

    info = rule_map[center]
    children = []
    seen = set()

    def _push(item):
        key = (item['type'], item.get('id') or item.get('name'), item.get('kind'))
        if key in seen:
            return
        seen.add(key)
        children.append(item)

    # if_sid / if_matched_sid 前置规则
    for dep in info.get('if_sid', []):
        _push(_rule_node(rule_map, str(dep), 'if_sid'))
    # if_group 依赖的分组
    for g in info.get('if_group', []):
        _push({
            'name': g, 'type': 'group', 'kind': 'if_group', 'label': f'[组] {g}',
            'count': len(group_members.get(g, [])),
        })
    # if_matched_group 依赖的分组
    for g in info.get('if_matched_group', []):
        _push({
            'name': g, 'type': 'group', 'kind': 'if_matched_group', 'label': f'[组] {g}',
            'count': len(group_members.get(g, [])),
        })

    node = _rule_node(rule_map, center, 'root')
    return jsonify({'success': True, 'data': {'node': node, 'children': children}})


@api_bp.route('/api/chain/group/<path:group_name>', methods=['GET'])
def chain_group(group_name):
    """分组下打该标签的规则列表（懒加载展开分组节点时调用）。"""
    cache = _get_rules()
    if cache is None:
        return jsonify({'success': False, 'error': '无法获取规则数据'}), 500
    _, group_members = _build_index(cache)
    members = group_members.get(group_name, [])
    children = []
    for m in members[:50]:
        children.append(_rule_node({str(r['id']): r for r in members}, str(m['id']), 'member'))
    node = {
        'name': group_name, 'type': 'group', 'label': f'[组] {group_name}',
        'count': len(members),
    }
    return jsonify({
        'success': True,
        'data': {'node': node, 'children': children, 'total': len(members)},
    })


# ------------------------------------------------------------------ #
# 受控图谱
# ------------------------------------------------------------------ #
@api_bp.route('/api/graph', methods=['GET'])
def get_graph():
    """
    返回受控子图（避免全量渲染卡顿）。
    支持三种方式（可组合）：
      ?rule_id=5760&depth=2   以某规则为中心的依赖链
      ?groups=a,b,c           勾选的分组集合
      ?q=关键词                搜索命中 + 一跳依赖
    """
    cache = _get_rules()
    if cache is None:
        return jsonify({'success': False, 'error': '无法获取规则数据，请检查 Wazuh 连接'}), 500

    rule_map = {str(r['id']): r for r in cache['rules']}

    rule_id = request.args.get('rule_id', type=int)
    groups = request.args.get('groups', '')
    q = request.args.get('q', '').strip()
    depth = min(request.args.get('depth', default=2, type=int), 5)

    if rule_id is not None:
        center = str(rule_id)
        if center not in rule_map:
            return jsonify({'success': False, 'error': f'规则 #{rule_id} 不存在'}), 404
        ids = _gather_around(cache, {center}, depth)
        desc = f'规则 #{rule_id} 及 {depth} 层依赖链（含打标签的前置规则）'
    elif groups or q:
        gset = {g for g in groups.split(',') if g}
        ids = set()
        for r in cache['rules']:
            if q and q.lower() not in f"{r['id']} {r['description']} {' '.join(r.get('groups', []))}".lower():
                continue
            if gset and not (gset & set(r.get('groups', []))):
                continue
            ids.add(str(r['id']))
        if q:
            ids = _gather_around(cache, ids, 1)
        desc = f'分组=[{"、".join(sorted(gset)) or "全部"}] 关键词=[{q or "无"}]'
    else:
        return jsonify({'success': False, 'error': '请先选择分组、输入关键词或指定规则ID'}), 400

    if not ids:
        return jsonify({'success': True, 'data': {'nodes': [], 'edges': [], 'stats': {}, 'message': '没有匹配的规则'}})

    graph, err = _build_subgraph(cache, ids, desc)
    if err:
        return jsonify({'success': False, 'error': err}), 400
    return jsonify({'success': True, 'data': graph})


# ------------------------------------------------------------------ #
# 日志测试
# ------------------------------------------------------------------ #
@api_bp.route('/api/test', methods=['POST'])
def test_log():
    payload = request.get_json(silent=True) or {}
    log = (payload.get('log') or '').strip()
    if not log:
        return jsonify({'success': False, 'error': '请提供日志内容'}), 400
    result = wazuh.test_log(log)
    if result:
        return jsonify({'success': True, 'data': result})
    return jsonify({'success': False, 'error': 'logtest 失败，请检查日志内容与 Wazuh 配置'}), 500
