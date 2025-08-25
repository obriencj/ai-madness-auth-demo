"""
Setup configuration for ai_auth_backend package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ai_auth_backend",
    version="0.1.0",
    author="AI Madness Team",
    author_email="team@ai-madness.com",
    description="A self-hosted, open-source authentication service",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/ai-auth-backend",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Flask>=2.3.0",
        "Flask-SQLAlchemy>=3.0.0",
        "Flask-JWT-Extended>=4.5.0",
        "Flask-CORS>=4.0.0",
        "Flask-RESTX>=1.1.0",
        "SQLAlchemy>=2.0.0",
        "psycopg2-binary>=2.9.0",
        "redis>=4.5.0",
        "bcrypt>=4.0.0",
        "requests>=2.28.0",
        "gunicorn>=20.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-auth-backend=ai_auth_backend.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ai_auth_backend": ["py.typed"],
    },
)

# The end.
