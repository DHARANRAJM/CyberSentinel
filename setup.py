from setuptools import setup, find_packages

setup(
    name="cybersentinel",
    version="1.0.0",
    description="Automated Vulnerability Assessment Tool",
    author="CyberSentinel Team",
    author_email="contact@cybersentinel.com",
    packages=find_packages(),
    install_requires=[
        "python-nmap>=1.6.0",
        "scapy>=2.5.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2",
        "reportlab>=4.0.4",
        "jinja2>=3.1.2",
        "cryptography>=41.0.3",
        "tabulate>=0.9.0",
        "colorama>=0.4.6",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    entry_points={
        "console_scripts": [
            "cybersentinel=src.main:main",
        ],
    },
)
