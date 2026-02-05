# test_github_api.py
import requests
import yaml

def load_config():
    with open('config.yaml', 'r') as f:
        return yaml.safe_load(f)

def test_github_api():
    config = load_config()
    token = config['github']['token']
    
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    # 测试1: 检查速率限制
    print("1. 测试速率限制...")
    response = requests.get('https://api.github.com/rate_limit', headers=headers)
    if response.status_code == 200:
        rate_limit = response.json()
        print(f"速率限制状态: {rate_limit}")
    else:
        print(f"速率限制检查失败: {response.status_code}")
    
    # 测试2: 简单搜索测试
    print("\n2. 测试简单搜索...")
    params = {
        'q': 'stars:>10',
        'sort': 'stars',
        'order': 'desc',
        'per_page': 5
    }
    
    response = requests.get('https://api.github.com/search/repositories', 
                          headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()
        print(f"搜索成功，找到 {data.get('total_count', 0)} 个仓库")
        for repo in data.get('items', [])[:3]:
            print(f"  - {repo['full_name']} ({repo['stargazers_count']} stars)")
    else:
        print(f"搜索失败: {response.status_code}")
        print(f"响应内容: {response.text[:500]}")
    
    # 测试3: 检查用户权限
    print("\n3. 检查用户权限...")
    response = requests.get('https://api.github.com/user', headers=headers)
    if response.status_code == 200:
        user_info = response.json()
        print(f"用户: {user_info.get('login')}")
        print(f"权限: {user_info.get('type')}")
    else:
        print(f"用户信息获取失败: {response.status_code}")

if __name__ == "__main__":
    test_github_api()