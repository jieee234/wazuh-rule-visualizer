"""
本地规则缓存。

设计目标：
- 首次从 Wazuh 全量拉取规则并解析后写入本地 JSON，后续所有读接口优先读缓存（快）
- 用户点击"更新数据"时才重新全量拉取并覆盖缓存
"""
import json
import os
import time
from pathlib import Path

DATA_DIR = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))) / 'data'
CACHE_FILE = DATA_DIR / 'rules_cache.json'
CACHE_TMP = DATA_DIR / 'rules_cache.tmp'

# 进程内缓存：文件未变化时避免重复解析 JSON
_mem_cache = None
_mem_mtime = None


def load_cache():
    """读取本地缓存，返回 {updated_at, total, rules:[...]}；无缓存/损坏返回 None。"""
    if not CACHE_FILE.exists():
        return None
    mtime = CACHE_FILE.stat().st_mtime
    global _mem_cache, _mem_mtime
    if _mem_cache is not None and _mem_mtime == mtime:
        return _mem_cache
    try:
        with open(CACHE_FILE, encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get('rules'), list) and data['rules']:
            _mem_cache = data
            _mem_mtime = mtime
            return data
    except (json.JSONDecodeError, OSError) as e:
        print(f"[cache] 缓存读取失败: {e}")
    return None


def save_cache(rules):
    """把规则列表写入缓存（原子写入），返回缓存负载。"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        'updated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total': len(rules),
        'rules': rules,
    }
    with open(CACHE_TMP, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, separators=(',', ':'))
    os.replace(CACHE_TMP, CACHE_FILE)  # 原子替换，避免写一半
    global _mem_cache, _mem_mtime
    _mem_cache = payload
    _mem_mtime = CACHE_FILE.stat().st_mtime
    return payload


def cache_info():
    """返回缓存元信息（无规则内容）。"""
    cache = load_cache()
    if cache is None:
        return {'exists': False}
    return {
        'exists': True,
        'updated_at': cache.get('updated_at'),
        'total': cache.get('total'),
    }
