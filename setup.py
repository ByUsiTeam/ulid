from setuptools import setup, find_packages

setup(
    name="byusi-ulid",
    version="1.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        'base62>=1.0.0',
        'crcmod>=1.7'
    ],
    entry_points={
        'console_scripts': [
            'ulid-tool=ulid.cli:main',
        ],
    },
    python_requires='>=3.8',
)