"""
图构建器

把规则列表（原始 API 数据）转换为前端可渲染的图结构：
- 节点：规则节点 + 分组节点
- 边：
    * if_sid / if_matched_sid → 规则依赖另一条规则（方向：本规则 → 被依赖规则）
    * if_group / if_matched_group → 规则依赖某个分组（本规则 → 分组节点）
    * member → 规则属于某个分组（本规则 → 分组节点）
"""
from app.core.rule_parser import RuleParser


class GraphBuilder:
    @staticmethod
    def _node_key(node_id):
        """规则节点统一用 str(id) 作 key，与 API 返回的 int/str 兼容。"""
        return str(node_id)

    @classmethod
    def build_graph(cls, rules):
        """从原始规则列表构建图。rules 为 API 返回的 affected_items 列表。"""
        parsed_rules = {}
        for rule in rules:
            parsed = RuleParser.extract_dependencies(rule)
            # 补充展示字段
            parsed.setdefault('level', rule.get('level', 0))
            parsed.setdefault('description', rule.get('description', ''))
            parsed.setdefault('file', rule.get('file', ''))
            parsed_rules[cls._node_key(parsed['id'])] = parsed

        return cls.build_graph_from_parsed(parsed_rules)

    @classmethod
    def build_graph_from_parsed(cls, parsed_rules):
        """从已解析的 {id: parsed_info} 构建图。"""
        nodes, edges = [], []
        node_keys = set()          # 规则 key
        group_keys = set()         # 分组 key
        edge_keys = set()          # 去重
        group_names = {}           # group key -> display name

        def _ensure_group(group_name):
            """确保分组节点存在，返回其 key。"""
            gkey = f"group:{group_name}"
            if gkey not in group_keys:
                group_keys.add(gkey)
                nodes.append({
                    'id': gkey,
                    'label': f"[组] {group_name}",
                    'type': 'group',
                    'name': group_name,
                })
            group_names[gkey] = group_name
            return gkey

        def _add_edge(source, target, edge_type):
            ekey = (source, target, edge_type)
            if ekey in edge_keys:
                return
            edge_keys.add(ekey)
            edges.append({
                'source': source,
                'target': target,
                'type': edge_type,
            })

        # 第一遍：建立所有规则节点 + 分组节点
        for rule_id, info in parsed_rules.items():
            key = cls._node_key(rule_id)
            if key not in node_keys:
                node_keys.add(key)
                nodes.append({
                    'id': key,
                    'label': f"#{key}",
                    'level': info.get('level', 0),
                    'description': info.get('description', ''),
                    'groups': info.get('groups', []),
                    'file': info.get('file', ''),
                    'type': 'rule',
                    'if_sid': info.get('if_sid', []),
                    'if_group': info.get('if_group', []),
                    'if_matched_group': info.get('if_matched_group', []),
                })

        # 第二遍：建立边
        for rule_id, info in parsed_rules.items():
            key = cls._node_key(rule_id)

            # 1) 前置规则依赖（if_sid / if_matched_sid）
            for dep_sid in info.get('if_sid', []):
                dep_key = cls._node_key(dep_sid)
                # 被依赖规则可能不在本次拉取范围：补一个"缺失"节点
                if dep_key not in node_keys:
                    node_keys.add(dep_key)
                    nodes.append({
                        'id': dep_key,
                        'label': f"#{dep_key}",
                        'level': None,
                        'description': '（不在本次拉取范围 / 未找到）',
                        'groups': [],
                        'file': '',
                        'type': 'rule',
                        'missing': True,
                    })
                _add_edge(key, dep_key, 'if_sid')

            # 2) 分组依赖（if_group / if_matched_group）
            for g in info.get('if_group', []):
                gkey = _ensure_group(g)
                _add_edge(key, gkey, 'if_group')
            for g in info.get('if_matched_group', []):
                gkey = _ensure_group(g)
                _add_edge(key, gkey, 'if_matched_group')

            # 3) 规则归属分组（member）
            for g in info.get('groups', []):
                gkey = _ensure_group(g)
                _add_edge(key, gkey, 'member')

        return {
            'nodes': nodes,
            'edges': edges,
            'stats': {
                'rule_count': len(node_keys),
                'group_count': len(group_keys),
                'edge_count': len(edges),
                'if_sid_edges': sum(1 for e in edges if e['type'] == 'if_sid'),
                'group_edges': sum(
                    1 for e in edges if e['type'] in ('if_group', 'if_matched_group')
                ),
                'member_edges': sum(1 for e in edges if e['type'] == 'member'),
            },
        }
