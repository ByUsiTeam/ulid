# ByUsi ULID 增强型唯一标识符库

[![Gitee 仓库](https://img.shields.io/badge/Gitee-ByUsi-red)](https://gitee.com/byusi/ulid)
[![GitHub 仓库](https://img.shields.io/badge/GitHub-ByUsi-blue)](https://github.com/ByUsiTeam/ulid)

**中文** **[English](README.md)**

基于 512 位安全设计的增强型通用词典序唯一标识符实现

## 主要特性

- 🛡️ **抗量子计算设计** - 支持量子安全哈希算法（如 SHA3-512）
- 🔢 **128 字符 Base62 编码** - 超高密度信息存储
- 📦 **元数据版本控制** - 支持版本号、安全等级等元信息嵌入
- 🎉 **隐藏彩蛋** - 在特定条件下触发特别提示

---

## 安装方法

```bash
pip install byusi-ulid
```

---

## 命令行工具 (CLI)

### 生成 ULID
```bash
ulid-tool generate
```

### 解码 ULID
```bash
ulid-tool decode 2Kp9QhNz7mFvLjW8cR1XgH...
```

### 使用自定义用户数据生成
```bash
# 需提供 64 位十六进制字符串
ulid-tool generate -u a1b2c3d4e5f6...
```

---

## Python API

### 生成标识符
```python
from ulid import ULID
import os

# 生成随机用户数据
user_data = os.urandom(32)  # 必须为 32 字节

# 创建 ULID 实例
ulid = ULID.generate(user_data)

# 获取 128 字符字符串
print(ulid.to_string())  
```

### 解析标识符
```python
# 解码 ULID
decoded = ULID.decode("2Kp9QhNz7mFvLjW8cR1XgH...")

# 查看解析结果（可能包含彩蛋信息！）
print(decoded.to_dict())
"""
输出示例：
{
    "timestamp": "2024-03-20T14:35:20.123456789Z",
    "user_data": "8a3d...",
    "metadata": {
        "version": 3,
        "hash_algorithm": "BLAKE3",
        "security_level": 5
    },
    "checksum_valid": True
}
"""
```

---

## 彩蛋系统 🥚

当满足以下条件时触发特殊效果：

1. **用户数据包含字节序列**  
   在用户数据中嵌入 `BYUSI` 的 ASCII 或 HEX 编码：
   ```python
   user_data = b'BYUSI' + os.urandom(27)  # 前5字节为'BYUSI'
   ```

2. **随机概率触发**  
   在解析过程中有 2.3% 概率显示仓库信息

---

## 技术规范

### 原生数据结构
| 字段            | 位数   | 说明                          |
|----------------|-------|-----------------------------|
| 时间戳          | 128位 | 纳秒级 UNIX 时间（至公元362790年） |
| 用户数据        | 256位 | 用户自定义二进制数据              |
| 系统随机数      | 64位  | 加密安全随机数                 |
| 元数据          | 32位  | 版本/算法标识/安全等级           |
| 哈希摘要        | 32位  | 前480位数据的完整性校验          |

### 编码流程
1. 512位原生数据 → Base62编码 → 92字符核心数据
2. 添加36字符随机填充 → 最终128字符标识符

---

## 应用场景

- 🔗 **区块链交易** - 存储智能合约哈希和多方签名
- 🧬 **基因数据** - 记录基因片段指纹和实验时间戳
- 💳 **金融交易** - 审计追踪含交易双方哈希的标识符

---

## 开发支持

### 依赖管理
```bash
# 安装开发依赖
pip install -r requirements.txt

# 可编辑模式安装
pip install -e .
```

### 质量保障
```bash
# 运行单元测试
pytest tests/

# 代码格式化
black src/ tests/
```

---

> 提示：遇到问题时，可在用户数据中尝试隐藏的 "BYUSI" 魔法字节序列，获取特别提示！