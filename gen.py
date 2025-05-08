import base64
import yaml
import json
import urllib.parse

# 定义基础 yml 文件路径和代理链接文件路径
BASE_YML_PATH = "custom.yml"  # 基础 yml 文件路径
PROXY_LINKS_PATH = "proxy_links.txt"  # 代理链接文档路径
OUTPUT_YML_PATH = "merged.yml"  # 输出合成后的 yml 文件路径

def parse_vmess(link):
    """解析 vmess 链接"""
    try:
        decoded = base64.b64decode(link[8:]).decode("utf-8")
        config = json.loads(decoded)
        return {
            "name": config.get("ps", "Unnamed"),
            "type": "vmess",
            "server": config["add"],
            "port": int(config["port"]),
            "uuid": config["id"],
            "alterId": int(config.get("aid", 0)),
            "cipher": config.get("scy", "auto"),
            "tls": config.get("tls", False) if isinstance(config.get("tls"), bool) else False,
            "network": config.get("net", "tcp"),
            "udp": True
        }
    except Exception as e:
        print(f"解析 vmess 链接失败: {e}")
        return None

def parse_vless(link):
    """解析 vless 链接"""
    try:
        parts = link[8:].split("?")
        main = parts[0].split("@")
        uuid, server_port = main[0], main[1]
        server, port = server_port.split(":")
        params = dict(param.split("=") for param in parts[1].split("&"))
        return {
            "name": urllib.parse.unquote(params.get("remark", "Unnamed")),
            "type": "vless",
            "server": server,
            "port": int(port),
            "uuid": uuid,
            "cipher": params.get("encryption", "none"),
            "tls": params.get("security", "none") == "tls",
            "udp": True
        }
    except Exception as e:
        print(f"解析 vless 链接失败: {e}")
        return None

def parse_ss(link):
    """解析 ss 链接"""
    try:
        # ss://[method:password]@host:port#name
        decoded = base64.urlsafe_b64decode(link[5:].split("@")[0]).decode("utf-8")
        method, password = decoded.split(":")
        host_port = link.split("@")[1]
        host, port = host_port.split("#")[0].split(":")
        name = urllib.parse.unquote(host_port.split("#")[1])
        return {
            "name": name,
            "type": "ss",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password,
            "tls": False,  # ss 默认没有 tls
            "udp": True
        }
    except Exception as e:
        print(f"解析 ss 链接失败: {e}")
        return None

def parse_trojan(link):
    """解析 trojan 链接"""
    try:
        # trojan://password@host:port?sni=example.com#name
        parsed = urllib.parse.urlparse(link)
        name = urllib.parse.unquote(parsed.fragment)
        return {
            "name": name,
            "type": "trojan",
            "server": parsed.hostname,
            "port": int(parsed.port),
            "password": parsed.username,
            "sni": parsed.query.split("sni=")[-1] if "sni=" in parsed.query else "",
            "tls": True,  # trojan 通常默认启用 tls
            "udp": True
        }
    except Exception as e:
        print(f"解析 trojan 链接失败: {e}")
        return None

def load_base_yml(path):
    """加载基础 yml 文件"""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_proxy_links(path):
    """加载代理链接文档"""
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def ensure_unique_names(proxies):
    """确保代理名称唯一，如果重复则追加序号"""
    name_count = {}
    for proxy in proxies:
        original_name = proxy["name"]
        if original_name not in name_count:
            name_count[original_name] = 0
        else:
            name_count[original_name] += 1
            proxy["name"] = f"{original_name}-{name_count[original_name]}"
    return proxies

def merge_proxies(base_config, proxies):
    """合并代理到基础配置"""
    if "proxies" not in base_config:
        base_config["proxies"] = []

    # 确保代理名称唯一
    proxies = ensure_unique_names(proxies)

    base_config["proxies"].extend(proxies)

    # 更新 proxy-groups 中的 🔰 选择节点
    for group in base_config.get("proxy-groups", []):
        if group.get("name") == "🔰 选择节点":
            if "proxies" not in group:
                group["proxies"] = []
            group["proxies"].extend([proxy["name"] for proxy in proxies])
            break
    return base_config

def save_merged_yml(config, path):
    """保存合并后的 yml 文件"""
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True)

def main():
    # 加载基础 yml 文件
    base_config = load_base_yml(BASE_YML_PATH)

    # 加载代理链接
    proxy_links = load_proxy_links(PROXY_LINKS_PATH)

    # 解析代理链接
    proxies = []
    for link in proxy_links:
        if link.startswith("vmess://"):
            proxy = parse_vmess(link)
        elif link.startswith("vless://"):
            proxy = parse_vless(link)
        elif link.startswith("ss://"):
            proxy = parse_ss(link)
        elif link.startswith("trojan://"):
            proxy = parse_trojan(link)
        else:
            print(f"未知的代理链接格式: {link}")
            continue
        if proxy:
            proxies.append(proxy)

    # 合并代理到基础配置
    merged_config = merge_proxies(base_config, proxies)

    # 保存合并后的 yml 文件
    save_merged_yml(merged_config, OUTPUT_YML_PATH)
    print(f"合并后的配置已保存到 {OUTPUT_YML_PATH}")

if __name__ == "__main__":
    main()