import os
import time
import base62
import crcmod
from hashlib import blake2b, sha3_512
from typing import Dict, Optional

class ULIDError(Exception):
    """Base exception for ULID operations"""

class ULID:
    def __init__(
        self,
        timestamp: bytes,
        user_data: bytes,
        sys_rand: bytes,
        metadata: bytes,
        hash_digest: bytes,
    ):
        self.timestamp = timestamp  # 16 bytes (128 bits)
        self.user_data = user_data  # 32 bytes (256 bits)
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
        if len(user_data) != 32:
            raise ULIDError("User data must be 32 bytes")

        # Generate components
        timestamp_bytes = cls._get_timestamp()
        sys_rand = os.urandom(8)
        metadata = cls._encode_metadata(version, hash_algo, security_level)
        
        # Calculate hash digest
        hash_input = timestamp_bytes + user_data + sys_rand + metadata
        hash_digest = cls._compute_hash(hash_input, hash_algo)
        
        return cls(timestamp_bytes, user_data, sys_rand, metadata, hash_digest)

    @classmethod
    def decode(cls, ulid_str: str) -> "ULID":
        if len(ulid_str) != 128:
            raise ULIDError("Invalid ULID length")

        encoded_part = ulid_str[:92]
        try:
            raw_data = base62.decode(encoded_part).to_bytes(64, 'big')
        except (ValueError, TypeError) as e:
            raise ULIDError("Invalid Base62 encoding") from e

        # Split components
        timestamp = raw_data[:16]
        user_data = raw_data[16:48]
        sys_rand = raw_data[48:56]
        metadata = raw_data[56:60]
        hash_digest = raw_data[60:64]

        # Validate hash
        hash_input = timestamp + user_data + sys_rand + metadata
        metadata_info = cls._decode_metadata(metadata)
        computed_digest = cls._compute_hash(hash_input, metadata_info["hash_algorithm"])
        
        if computed_digest != hash_digest:
            raise ULIDError("Hash digest mismatch")

        return cls(timestamp, user_data, sys_rand, metadata, hash_digest)

    def to_string(self) -> str:
        encoded = base62.encodebytes(
            self.timestamp + self.user_data + self.sys_rand + 
            self.metadata + self.hash_digest
        ).ljust(92, '0')[:92]
        padding = self._generate_padding()
        return encoded + padding

    def to_dict(self) -> Dict:
        result = {
            "timestamp": self._parse_timestamp(),
            "user_data": self.user_data.hex(),
            "sys_rand": self.sys_rand.hex(),
            "metadata": self._decode_metadata(self.metadata),
            "hash_digest": self.hash_digest.hex(),
            "checksum_valid": True,
        }
        if secret_msg := self._check_easter_egg():
            result["secret"] = secret_msg
        return result

    @staticmethod
    def _get_timestamp() -> bytes:
        ns = time.time_ns()
        return ns.to_bytes(16, "big", signed=False)

    @classmethod
    def _encode_metadata(cls, version: int, hash_algo: str, security_level: int) -> bytes:
        hash_code = {
            "crc32": 0,
            "blake2b": 1,
            "sha3-512": 2
        }.get(hash_algo, 0)
        return (
            (version & 0x0F) << 28 |
            (hash_code & 0x0F) << 24 |
            (security_level & 0x0F) << 20
        ).to_bytes(4, "big")

    @classmethod
    def _decode_metadata(cls, metadata_bytes: bytes) -> Dict:
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
        algorithm = algorithm.lower()
        if algorithm == "crc32":
            crc32 = crcmod.predefined.Crc("crc-32")
            crc32.update(data)
            return crc32.digest()
        elif algorithm == "blake2b":
            return blake2b(data, digest_size=4).digest()
        elif algorithm == "sha3-512":
            return sha3_512(data).digest()[:4]
        raise ULIDError(f"Unsupported hash algorithm: {algorithm}")

    def _parse_timestamp(self) -> str:
        ns = int.from_bytes(self.timestamp, "big")
        sec, ns = divmod(ns, 1_000_000_000)
        dt = time.gmtime(sec)
        return f"{time.strftime('%Y-%m-%dT%H:%M:%S', dt)}.{ns:09d}Z"

    def _generate_padding(self) -> str:
        padding = base62.encodebytes(os.urandom(27)).ljust(36, '0')[:36]
        if os.urandom(1)[0] < 6:  # 2.3%概率插入彩蛋
            repo_info = "ByUsi Repos: gitee.com/byusi/ulid github.com/ByUsiTeam/ulid"
            encoded_repo = base62.encodebytes(repo_info.encode()[:27])
            return encoded_repo.ljust(36, '0')[:36]
        return padding

    def _check_easter_egg(self) -> Optional[str]:
        markers = [b"BYUSI", bytes.fromhex("4279555349")]
        for marker in markers:
            if marker in self.user_data:
                return "🎉 Discover ByUsi! Repositories: " \
                      "gitee.com/byusi/ulid | github.com/ByUsiTeam/ulid"
        return None