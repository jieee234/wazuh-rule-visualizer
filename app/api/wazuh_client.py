"""
Wazuh API 客户端

负责与 Wazuh Manager 的 REST API 通信：
- 认证（获取 JWT token）
- 拉取规则列表（支持分页 / 全量）
- 获取单条规则详情
- 日志测试（logtest）

兼容 Wazuh 4.x。logtest 端点在新版为 POST、旧版为 PUT，自动探测。
"""
import requests
import urllib3

from config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhClient:
    def __init__(self):
        self.base_url = f"https://{Config.WAZUH_HOST}:{Config.WAZUH_PORT}"
        self.username = Config.WAZUH_USERNAME
        self.password = Config.WAZUH_PASSWORD
        self.token = None
        self.timeout = Config.REQUEST_TIMEOUT
        self._headers = {}

    # ------------------------------------------------------------------ #
    # 认证
    # ------------------------------------------------------------------ #
    def authenticate(self):
        """获取并缓存 JWT token，返回是否成功。"""
        url = f"{self.base_url}/security/user/authenticate"
        try:
            resp = requests.post(
                url,
                auth=(self.username, self.password),
                verify=False,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                self.token = data.get('token')
                self._headers = {
                    'Authorization': f"Bearer {self.token}",
                    'Content-Type': 'application/json',
                }
                return True
            else:
                print(f"[WazuhClient] 认证失败 HTTP {resp.status_code}: {resp.text[:200]}")
                return False
        except requests.exceptions.SSLError as e:
            print(f"[WazuhClient] SSL 错误（若证书不受信任，verify=False 已禁用校验）: {e}")
            return False
        except requests.exceptions.ConnectionError as e:
            print(f"[WazuhClient] 连接失败，请检查地址/端口/网络: {e}")
            return False
        except Exception as e:
            print(f"[WazuhClient] 认证异常: {e}")
            return False

    def _ensure_token(self):
        """确保有 token；没有或失效则重新认证。"""
        if not self.token:
            return self.authenticate()
        return True

    def _api_get(self, path, params=None):
        """带 token 自动重试的 GET 请求。"""
        if not self._ensure_token():
            return None
        url = f"{self.base_url}{path}"
        try:
            resp = requests.get(
                url, headers=self._headers, params=params,
                verify=False, timeout=self.timeout,
            )
            if resp.status_code == 401:  # token 过期，重试一次
                if self.authenticate():
                    resp = requests.get(
                        url, headers=self._headers, params=params,
                        verify=False, timeout=self.timeout,
                    )
                else:
                    return None
            if resp.status_code == 200:
                return resp.json().get('data', {})
            print(f"[WazuhClient] GET {path} 失败 HTTP {resp.status_code}: {resp.text[:200]}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[WazuhClient] GET {path} 异常: {e}")
            return None

    # ------------------------------------------------------------------ #
    # 规则
    # ------------------------------------------------------------------ #
    def get_rules(self, limit=None, offset=0):
        """
        获取规则列表，返回 affected_items 数组；失败返回 None。
        limit 传 None 表示用 Config.RULE_LIMIT。
        """
        limit = Config.RULE_LIMIT if limit is None else limit
        params = {'limit': limit, 'offset': offset}
        data = self._api_get('/rules', params=params)
        if data is None:
            return None
        items = data.get('affected_items', [])
        if not items and data.get('total_affected_items', 0) == 0:
            # 空集也可能是真的没有规则
            return []
        return items

    def get_all_rules(self, batch=500, progress=None):
        """
        分页拉取全部规则。
        返回 (rules_list, total)；失败返回 (None, 0)。
        progress 为可选回调 progress(done, total)。
        """
        if not self._ensure_token():
            return None, 0
        # 先探测总量
        data = self._api_get('/rules', params={'limit': 1, 'offset': 0})
        if data is None:
            return None, 0
        total = data.get('total_affected_items', 0)
        all_rules, offset = [], 0
        while offset < total:
            batch_rules = self.get_rules(limit=batch, offset=offset)
            if batch_rules is None:
                return None, total
            all_rules.extend(batch_rules)
            offset += batch
            if progress:
                progress(offset, total)
        return all_rules, total

    def get_rule_by_id(self, rule_id):
        """获取指定规则详情，不存在返回 None。兼容新旧版 API。"""
        # 新版 Wazuh 4.4+：/rules/{id} 端点已移除，改用 q 过滤（4.14 实测可用）
        data = self._api_get('/rules', params={'q': f'id={rule_id}', 'limit': 1})
        if data is None:
            return None
        items = data.get('affected_items', [])
        if items:
            return items[0]
        # 兜底：旧版路径 /rules/{id}
        data = self._api_get(f"/rules/{rule_id}")
        if data is None:
            return None
        items = data.get('affected_items', [])
        return items[0] if items else None

    def get_rule_file(self, filename):
        """获取指定规则文件的内容（Wazuh API 返回 JSON 化的 XML），失败返回 None。"""
        data = self._api_get(f'/rules/files/{filename}')
        if data is None:
            return None
        items = data.get('affected_items', [])
        return items[0] if items else None

    # ------------------------------------------------------------------ #
    # 日志测试
    # ------------------------------------------------------------------ #
    def test_log(self, log_message):
        """
        用 logtest 测试一条日志命中哪条规则。
        新版 Wazuh 4.10+/4.14：PUT /logtest，参数 event / log_format / location（实测）
        旧版：POST /logtest，参数 log。自动降级。
        """
        if not self._ensure_token():
            return None
        url = f"{self.base_url}/logtest"
        new_payload = {"event": log_message, "log_format": "syslog", "location": "syslog"}
        old_payload = {"log": log_message, "token": self.token}
        for method, payload in (('put', new_payload), ('post', old_payload)):
            try:
                resp = getattr(requests, method)(
                    url, headers=self._headers, json=payload,
                    verify=False, timeout=self.timeout,
                )
                if resp.status_code in (200, 201):
                    return resp.json().get('data', resp.json())
            except requests.exceptions.RequestException as e:
                print(f"[WazuhClient] logtest {method} 异常: {e}")
        print("[WazuhClient] logtest 失败：PUT 与 POST 均已尝试")
        return None

    def update_config(self, host=None, port=None, username=None, password=None):
        """动态更新连接配置（前端设置面板）。传入 None 的字段保持不变。"""
        changed = False
        if host is not None and host != Config.WAZUH_HOST:
            Config.WAZUH_HOST = host
            changed = True
        if port is not None and port != Config.WAZUH_PORT:
            Config.WAZUH_PORT = int(port)
            changed = True
        if username is not None and username != Config.WAZUH_USERNAME:
            Config.WAZUH_USERNAME = username
            changed = True
        if password is not None and password != Config.WAZUH_PASSWORD:
            Config.WAZUH_PASSWORD = password
            changed = True
        if changed:
            self.base_url = f"https://{Config.WAZUH_HOST}:{Config.WAZUH_PORT}"
            self.token = None
            self._headers = {}
        return changed

    def status(self):
        """返回连接信息（供前端展示）。"""
        ok = self.authenticate()
        return {
            'status': 'ok' if ok else 'failed',
            'server': self.base_url,
            'user': self.username,
        }
