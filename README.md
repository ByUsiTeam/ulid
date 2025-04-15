# ByUsi ULID

[![Gitee](https://img.shields.io/badge/Gitee-ByUsi-red)](https://gitee.com/byusi/ulid)
[![GitHub](https://img.shields.io/badge/GitHub-ByUsi-blue)](https://github.com/ByUsiTeam/ulid)

Enhanced ULID implementation with 512-bit security features.

## Features
- 🛡️ Quantum-resistant design
- 🔢 128-character Base62 encoding
- 📦 Metadata versioning support
- 🎉 Hidden Easter eggs!

## Installation
```bash
pip install byusi-ulid
```

## CLI Usage
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

## Easter Eggs
Try including "ByUsi" in user data 😉