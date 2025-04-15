# ByUsi ULID

[![Gitee](https://img.shields.io/badge/Gitee-ByUsi-red)](https://gitee.com/byusi/ulid)
[![GitHub](https://img.shields.io/badge/GitHub-ByUsi-blue)](https://github.com/ByUsiTeam/ulid)

**中文** **[English](README.md)**

具有512位安全功能增强的ULID实现。

## 特征
- 🛡️ 抗量子设计
- 🔢 128个字符的base62编码
- 📦 元数据版本支持

## 安装
```bash
pip install byusi-ulid
```

## CLI用法
```bash
# Generate ULID
ulid-tool generate

# Decode ULID
ulid-tool decode 2Kp9QhNz7mFvLjW8cR1XgH...

# Generate with custom user data
ulid-tool generate -u a1b2c3... (64 hex chars)
```

## Python API
```python
from ulid import ULID
import os

# Generate
user_data = os.urandom(32)
ulid = ULID.generate(user_data)
print(ulid.to_string())

# Decode
decoded = ULID.decode("2Kp9QhNz7mFvLjW8cR1XgH...")
print(decoded.to_dict())  # May contain secrets!
```

## 彩蛋
尝试在用户数据中包括“BYUSI”😉