"""
规则解析器

从 Wazuh API 返回的单条规则对象中提取依赖关系。

Wazuh 4.x 的 /rules API 返回的规则结构（简化）：
{
    "id": 1002,
    "level": 5,
    "description": "...",
    "groups": ["syslog", "local"],
    "details": {
        "if_sid": 1001,             # 可单值或数组
        "if_matched_sid": "1001,1002",
        "if_group": "syslog",
        "if_matched_group": ["...", "..."],
        "group": ["syslog"],
        ...
    },
    "file": "local_rules.xml"
}

也兼容从规则 XML 字符串（老版本 API 或本地规则文件）解析。
"""
import re

# XML 标签 → 内部字段名
_XML_TAG_FIELD = {
    'if_sid': 'if_sid',
    'if_matched_sid': 'if_sid',           # 统一归入 if_sid（也是前置规则依赖）
    'if_group': 'if_group',
    'if_matched_group': 'if_matched_group',
    'group': 'groups',
}


def _to_list(value):
    """把单值 / 逗号分隔字符串 / 列表统一转成去重后的字符串列表。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        raw = value
    else:
        raw = [value]
    out = []
    for item in raw:
        for part in str(item).split(','):
            part = part.strip()
            if part and part not in out:
                out.append(part)
    return out


class RuleParser:
    # ------------------------------------------------------------------ #
    # 主入口：从 API 规则对象解析
    # ------------------------------------------------------------------ #
    @staticmethod
    def extract_dependencies(rule):
        """
        从一条规则对象中提取依赖关系。

        返回：
        {
            'id': int|str,               # 规则 ID
            'if_sid': [int...],          # 依赖的前置规则 ID（if_sid / if_matched_sid）
            'if_group': [str...],        # 依赖的分组（if_group）
            'if_matched_group': [str...],# 依赖的日志匹配分组（if_matched_group）
            'groups': [str...],          # 规则自身所属分组
        }
        """
        rule_id = rule.get('id') or rule.get('rule_id')
        details = rule.get('details') or {}
        # 若 API 返回的是 XML 字符串（老版本），走 XML 解析
        if isinstance(details, str):
            return RuleParser.parse_xml_rule(details, rule_id=rule_id)

        if_sid = _to_list(details.get('if_sid')) + _to_list(details.get('if_matched_sid'))
        # 部分 API 版本把 if_sid 以逗号字符串给出，_to_list 已处理

        return {
            'id': rule_id,
            'if_sid': [int(x) for x in if_sid if str(x).isdigit()],
            'if_group': _to_list(details.get('if_group')),
            'if_matched_group': _to_list(details.get('if_matched_group')),
            'groups': _to_list(rule.get('groups')) + _to_list(details.get('group')),
        }

    # ------------------------------------------------------------------ #
    # XML 解析（老版本 API / 本地规则文件）
    # ------------------------------------------------------------------ #
    @staticmethod
    def parse_xml_rule(xml_content, rule_id=None):
        """
        从规则 XML 字符串中解析依赖。
        if_sid / if_matched_sid 使用 findall，可提取多个。
        """
        if not xml_content:
            return {
                'id': rule_id, 'if_sid': [], 'if_group': [],
                'if_matched_group': [], 'groups': [],
            }

        def extract(tag):
            matches = re.findall(rf'<{tag}>([^<]+)</{tag}>', xml_content)
            out = []
            for m in matches:
                for part in m.split(','):
                    part = part.strip()
                    if part and part not in out:
                        out.append(part)
            return out

        if_sid = extract('if_sid') + extract('if_matched_sid')
        return {
            'id': rule_id,
            'if_sid': [int(x) for x in if_sid if x.isdigit()],
            'if_group': extract('if_group'),
            'if_matched_group': extract('if_matched_group'),
            'groups': extract('group'),
        }
