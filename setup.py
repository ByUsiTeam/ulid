from setuptools import setup, find_packages

# 默认版本号（会被CI流程覆盖）
DEFAULT_VERSION = "1.1.2" 

setup(
    name="byusi-ulid",
    version=DEFAULT_VERSION,  # CI流程中会被sed替换
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        'pybase62>=1.0.0',
        'crcmod>=1.7'
    ],
    entry_points={
        'console_scripts': [
            'ulid-tool=ulid.cli:main',
        ],
    }
)