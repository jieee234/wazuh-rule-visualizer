#!/usr/bin/env python3
"""
离线自检：用模拟规则数据验证 依赖解析 + 图构建 逻辑，无需连接真实 Wazuh。

用法：python scripts/selftest.py
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.core.rule_parser import RuleParser
from app.core.graph_builder import GraphBuilder

# 模拟 Wazuh API 返回的规则（含 details 依赖字段）
MOCK_RULES = [
    {
        "id": 1001, "level": 3, "description": "SSH authentication failure",
        "groups": ["syslog", "sshd"],
        "file": "sshd_rules.xml",
        "details": {"group": ["syslog", "sshd"], "id": 1001},
    },
    {
        "id": 1002, "level": 5, "description": "Multiple SSH failures",
        "groups": ["syslog", "sshd"],
        "file": "sshd_rules.xml",
        "details": {"if_sid": 1001, "group": ["syslog", "sshd"]},
    },
    {
        "id": 1003, "level": 10, "description": "SSH brute force attack",
        "groups": ["syslog", "sshd", "attack"],
        "file": "sshd_rules.xml",
        "details": {"if_sid": "1002", "if_group": "syslog", "group": ["syslog", "sshd", "attack"]},
    },
    {
        "id": 1004, "level": 12, "description": "Auth failure root with if_matched",
        "groups": ["syslog"],
        "file": "local_rules.xml",
        "details": {"if_matched_sid": [1002, 1003], "if_matched_group": "attack", "group": ["syslog"]},
    },
]


def check(name, cond):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name}")
    return cond


def main():
    print("=" * 56)
    print("离线自检：规则依赖解析 + 图构建")
    print("=" * 56)
    ok = True

    # 1) 单条规则解析
    print("\n[1] 单条规则依赖解析")
    p2 = RuleParser.extract_dependencies(MOCK_RULES[1])
    ok &= check("1002 if_sid=[1001]", p2["if_sid"] == [1001])
    p3 = RuleParser.extract_dependencies(MOCK_RULES[2])
    ok &= check("1003 if_sid=[1002]（字符串转 int）", p3["if_sid"] == [1002])
    ok &= check("1003 if_group=['syslog']", p3["if_group"] == ["syslog"])
    p4 = RuleParser.extract_dependencies(MOCK_RULES[3])
    ok &= check("1004 if_matched_sid 合并为 [1002,1003]", p4["if_sid"] == [1002, 1003])
    ok &= check("1004 if_matched_group=['attack']", p4["if_matched_group"] == ["attack"])

    # 2) XML 解析
    print("\n[2] XML 字符串解析")
    xml = '<rule id="2001" level="5"><if_sid>1001</if_sid><if_group>syslog,sshd</if_group><group>local</group></rule>'
    px = RuleParser.parse_xml_rule(xml)
    ok &= check("XML if_sid=[1001]", px["if_sid"] == [1001])
    ok &= check("XML if_group=[syslog,sshd]", px["if_group"] == ["syslog", "sshd"])
    ok &= check("XML groups=[local]", px["groups"] == ["local"])

    # 3) 图构建
    print("\n[3] 图构建")
    graph = GraphBuilder.build_graph(MOCK_RULES)
    node_ids = {n["id"]: n for n in graph["nodes"]}
    edge_types = {(e["source"], e["target"], e["type"]) for e in graph["edges"]}
    ok &= check("规则节点=4", sum(1 for n in graph["nodes"] if n["type"] == "rule") == 4)
    ok &= check("分组节点=3 (syslog/sshd/attack)", sum(1 for n in graph["nodes"] if n["type"] == "group") == 3)
    ok &= check("if_sid 边=4 (1002->1001, 1003->1002, 1004->1002, 1004->1003)",
                len([e for e in graph["edges"] if e["type"] == "if_sid"]) == 4)
    ok &= check("if_group 边=1 (1003->group:syslog)",
                ("1003", "group:syslog", "if_group") in edge_types)
    ok &= check("if_matched_group 边=1 (1004->group:attack)",
                ("1004", "group:attack", "if_matched_group") in edge_types)
    ok &= check("member 边=8（1001/1002 各2，1003 三条，1004 一条）",
                len([e for e in graph["edges"] if e["type"] == "member"]) == 8)

    # 4) 缺失节点补全
    print("\n[4] 缺失被依赖规则补全")
    lone = [{"id": 9001, "level": 4, "description": "引用不存在的规则",
             "groups": ["local"], "file": "x.xml", "details": {"if_sid": 9999}}]
    g2 = GraphBuilder.build_graph(lone)
    missing = [n for n in g2["nodes"] if n.get("missing")]
    ok &= check("补出缺失节点 #9999 且标记 missing", len(missing) == 1 and missing[0]["id"] == "9999")

    print("\n" + "=" * 56)
    print("自检结论：", "全部通过 ✅" if ok else "存在失败 ❌")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
