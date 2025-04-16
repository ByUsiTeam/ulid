import os
import time
import base62
import crcmod
from hashlib import blake2b, sha3_512
from typing import Dict, Optional

class ULIDError(Exception):
    """ULID操作基础异常类"""

class ULID:
    # 常量定义
    MAX_INT = (1 << 512) - 1  # 512位最大值
    BASE62_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    
    def __init__(
        self,
        timestamp: bytes,
        user_data: bytes,
        sys_rand: bytes,
        metadata: bytes,
        hash_digest: bytes,
    ):
        """初始化ULID组件"""
        self._validate_components(
            timestamp=timestamp,
            user_data=user_data,
            sys_rand=sys_rand,
            metadata=metadata,
            hash_digest=hash_digest
        )
        
        self.timestamp = timestamp  # 16 bytes (128 bits)
        self.user_data = user_data   # 32 bytes (256 bits)
        self.sys_rand = sys_rand    # 8 bytes (64 bits)
        self.metadata = metadata    # 4 bytes (32 bits)
        self.hash_digest = hash_digest  # 4 bytes (32 bits)

    @classmethod
    def generate(
        cls,
        user_data: bytes,
        version: int = 3,
        hash_algo: str = "blake2b",
        security_level: int = 5,
    ) -> "ULID":
        """生成新的ULID"""
        # 输入验证
        if len(user_data) != 32:
            raise ULIDError("用户数据必须为32字节")
        if version < 1 or version > 15:
            raise ULIDError("版本号必须在1-15范围内")
        if security_level < 0 or security_level > 15:
            raise ULIDError("安全等级必须在0-15范围内")

        # 生成组件
        timestamp_bytes = cls._get_timestamp()
        sys_rand = os.urandom(8)
        metadata = cls._encode_metadata(version, hash_algo, security_level)
        
        # 计算哈希摘要
        hash_input = timestamp_bytes + user_data + sys_rand + metadata
        hash_digest = cls._compute_hash(hash_input, hash_algo)
        
        return cls(timestamp_bytes, user_data, sys_rand, metadata, hash_digest)

    @classmethod
    def decode(cls, ulid_str: str) -> "ULID":
        """解码ULID字符串"""
        # 输入验证
        if len(ulid_str) != 128:
            raise ULIDError("无效的ULID长度（必须128字符）")
        if any(c not in cls.BASE62_CHARSET for c in ulid_str):
            raise ULIDError("包含无效的Base62字符")

        try:
            # 分割核心数据和填充
            encoded_part = ulid_str[:92]
            padding = ulid_str[92:]  # 保留填充数据供后续扩展使用
            
            # 安全解码
            raw_data = cls._safe_base62_decode(encoded_part)
            
            # 拆分组件
            components = {
                "timestamp": raw_data[:16],
                "user_data": raw_data[16:48],
                "sys_rand": raw_data[48:56],
                "metadata": raw_data[56:60],
                "hash_digest": raw_data[60:64]
            }
            
            # 完整性验证
            cls._validate_components(**components)
            
            # 哈希校验
            hash_input = b"".join([components["timestamp"], 
                                components["user_data"],
                                components["sys_rand"],
                                components["metadata"]])
            metadata_info = cls._decode_metadata(components["metadata"])
            computed_digest = cls._compute_hash(hash_input, metadata_info["hash_algorithm"])
            
            if computed_digest != components["hash_digest"]:
                raise ULIDError("哈希摘要不匹配")

            return cls(**components)
            
        except (ValueError, IndexError) as e:
            raise ULIDError(f"解码失败: {str(e)}") from e

    def to_string(self) -> str:
        """编码为128字符ULID字符串"""
        # 核心数据编码
        core_data = (
            self.timestamp + 
            self.user_data + 
            self.sys_rand + 
            self.metadata + 
            self.hash_digest
        )
        encoded_core = base62.encodebytes(core_data).zfill(92)[:92]
        
        # 生成加密安全填充
        padding = self._generate_padding()
        return encoded_core + padding

    def to_dict(self) -> Dict:
        """转换为解析字典"""
        result = {
            "timestamp": self._parse_timestamp(),
            "user_data": self.user_data.hex(),
            "sys_rand": self.sys_rand.hex(),
            "metadata": self._decode_metadata(self.metadata),
            "hash_digest": self.hash_digest.hex(),
            "checksum_valid": True,
        }
        # 彩蛋检测
        if secret_msg := self._detect_easter_egg():
            result["secret"] = secret_msg
        return result

    # region 私有方法
    @classmethod
    def _safe_base62_decode(cls, encoded: str) -> bytes:
        """安全渐进式Base62解码"""
        decoded_value = 0
        for char in encoded:
            index = cls.BASE62_CHARSET.index(char)
            decoded_value = decoded_value * 62 + index
            if decoded_value > cls.MAX_INT:
                raise ULIDError("解码数值超过512位限制")
        
        # 转换为64字节（512位）
        raw_bytes = bytearray()
        for _ in range(64):
            decoded_value, rem = divmod(decoded_value, 256)
            raw_bytes.insert(0, rem)  # 大端序
            
        if decoded_value != 0:
            raise ULIDError("解码数据长度异常")
            
        return bytes(raw_bytes)

    @staticmethod
    def _validate_components(**kwargs):
        """组件完整性验证"""
        expected_sizes = {
            "timestamp": 16,
            "user_data": 32,
            "sys_rand": 8,
            "metadata": 4,
            "hash_digest": 4
        }
        
        for name, data in kwargs.items():
            if len(data) != expected_sizes[name]:
                raise ULIDError(f"无效的{name}长度：{len(data)}字节")

    def _generate_padding(self) -> str:
        """生成随机填充"""
        # 加密安全随机填充
        random_padding = base62.encodebytes(os.urandom(27)).ljust(36, '0')[:36]
        
        # 彩蛋触发（2.3%概率）
        if os.urandom(1)[0] < 6:
            repo_info = "ByUsi仓库：gitee.com/byusi/ulid github.com/ByUsiTeam/ulid"
            return base62.encodebytes(repo_info.encode()[:18]).ljust(36, '0')[:36]
        return random_padding

    def _detect_easter_egg(self) -> Optional[str]:
        """彩蛋检测逻辑"""
        markers = [
            b"BYUSI", 
            bytes.fromhex("4279555349"),  # BYUSI的HEX表示
            b"\x42\x59\x55\x53\x49"       # ASCII字节表示
        ]
        for marker in markers:
            if marker in self.user_data:
                return "🎉 发现彩蛋！访问我们的仓库：gitee.com/byusi/ulid | github.com/ByUsiTeam/ulid"
        return None
    # endregion

    # region 辅助方法
    @staticmethod
    def _get_timestamp() -> bytes:
        """获取128位纳秒时间戳"""
        ns = time.time_ns()
        return ns.to_bytes(16, "big", signed=False)

    @classmethod
    def _encode_metadata(cls, version: int, hash_algo: str, security_level: int) -> bytes:
        """编码元数据"""
        hash_codes = {
            "crc32": 0,
            "blake2b": 1,
            "sha3-512": 2
        }
        return (
            (version & 0x0F) << 28 |
            (hash_codes.get(hash_algo, 0) & 0x0F) << 24 |
            (security_level & 0x0F) << 20
        ).to_bytes(4, "big")

    @classmethod
    def _decode_metadata(cls, metadata_bytes: bytes) -> Dict:
        """解码元数据"""
        metadata = int.from_bytes(metadata_bytes, "big")
        return {
            "version": (metadata >> 28) & 0x0F,
            "hash_algorithm": {
                0: "crc32",
                1: "blake2b",
                2: "sha3-512"
            }.get((metadata >> 24) & 0x0F, "unknown"),
            "security_level": (metadata >> 20) & 0x0F,
        }

    @classmethod
    def _compute_hash(cls, data: bytes, algorithm: str) -> bytes:
        """计算哈希摘要"""
        algorithm = algorithm.lower()
        if algorithm == "crc32":
            crc32 = crcmod.predefined.Crc("crc-32")
            crc32.update(data)
            return crc32.digest()
        elif algorithm == "blake2b":
            return blake2b(data, digest_size=4).digest()
        elif algorithm == "sha3-512":
            return sha3_512(data).digest()[:4]
        raise ULIDError(f"不支持的哈希算法：{algorithm}")

    def _parse_timestamp(self) -> str:
        """解析时间戳为ISO格式"""
        ns = int.from_bytes(self.timestamp, "big")
        sec, ns = divmod(ns, 1_000_000_000)
        dt = time.gmtime(sec)
        return f"{time.strftime('%Y-%m-%dT%H:%M:%S', dt)}.{ns:09d}Z"
    # endregion