"""
Setup script for the Authentication Engine package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="auth-engine",
    version="1.0.0",
    author="AI Madness Auth Demo",
    author_email="admin@example.com",
    description="A modular, configurable authentication system for Flask applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/auth-engine",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Flask>=2.0.0",
        "Flask-SQLAlchemy>=3.0.0",
        "Flask-JWT-Extended>=4.0.0",
        "Flask-CORS>=4.0.0",
        "bcrypt>=4.0.0",
        "redis>=4.0.0",
        "requests>=2.25.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-flask>=1.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
        "postgres": [
            "psycopg2-binary>=2.9.0",
        ],
        "mysql": [
            "PyMySQL>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "auth-engine=auth_engine.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)

# The end.
