#!/usr/bin/env python3
"""
测试 Wazuh API 连接、规则拉取与依赖解析。

用法（在项目根目录）：
    python scripts/test_api.py [--limit N] [--all] [--log "测试日志"]

示例：
    python scripts/test_api.py --limit 10
    python scripts/test_api.py --log "Oct 1 12:00:00 host sshd[123]: Failed password for root from 1.2.3.4"
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.api.wazuh_client import WazuhClient
from app.core.rule_parser import RuleParser


def fmt_ok(msg):
    print(f"  [OK] {msg}")


def fmt_fail(msg):
    print(f"  [FAIL] {msg}")


def main():
    args = sys.argv[1:]
    limit = 5
    fetch_all = '--all' in args
    test_log = None
    if '--limit' in args:
        limit = int(args[args.index('--limit') + 1])
    if '--log' in args:
        test_log = args[args.index('--log') + 1]

    print("=" * 60)
    print("Wazuh API 连接测试")
    print("=" * 60)

    client = WazuhClient()
    if not client.authenticate():
        fmt_fail("认证失败，请检查 .env 中的 WAZUH_HOST/PORT/USERNAME/PASSWORD")
        sys.exit(1)
    fmt_ok(f"认证成功 -> {client.base_url}")

    # 拉取规则
    if fetch_all:
        print("拉取全部规则...")
        rules, total = client.get_all_rules()
        if rules is None:
            fmt_fail("拉取全部规则失败")
            sys.exit(1)
        fmt_ok(f"共 {total} 条规则")
    else:
        rules = client.get_rules(limit=limit)
        if rules is None:
            fmt_fail("拉取规则失败")
            sys.exit(1)
        fmt_ok(f"获取 {len(rules)} 条规则（limit={limit}）")

    # 展示规则并统计依赖
    if_sid_total = 0
    if_group_total = 0
    print("\n规则列表：")
    for r in rules[:limit]:
        parsed = RuleParser.extract_dependencies(r)
        deps = parsed['if_sid']
        groups = parsed['if_group'] + parsed['if_matched_group']
        if_sid_total += len(deps)
        if_group_total += len(groups)
        dep_str = (f"if_sid={deps} if_group={groups}") if (deps or groups) else "无依赖"
        print(f"  #{r.get('id')} [L{r.get('level')}] {str(r.get('description', ''))[:40]}")
        print(f"      {dep_str}")

    print(f"\n依赖统计：if_sid 引用 {if_sid_total} 处，if_group 引用 {if_group_total} 处")

    # logtest
    if test_log:
        print("\n日志测试...")
        result = client.test_log(test_log)
        if result:
            rule = result.get('output', {}).get('rule') or result.get('matched_rule') or result.get('rule')
            msg = result.get('msg', 'matched')
            if rule:
                fmt_ok(f"命中规则 #{rule.get('id')} [L{rule.get('level')}] {rule.get('description', '')[:40]}")
            else:
                fmt_ok(f"返回：{msg} {str(rule or '')[:80]}")
        else:
            fmt_fail("logtest 失败")

    print("\n完成。")


if __name__ == '__main__':
    main()
