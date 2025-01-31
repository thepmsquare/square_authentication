from setuptools import find_packages, setup

package_name = "square_authentication"

setup(
    name=package_name,
    version="4.5.0",
    packages=find_packages(),
    package_data={
        package_name: ["data/*"],
    },
    install_requires=[
        "uvicorn>=0.24.0.post1",
        "fastapi>=0.104.1",
        "pydantic>=2.5.3",
        "bcrypt>=4.1.2",
        "pyjwt>=2.8.0",
        "requests>=2.32.3",
        "cryptography>=42.0.7",
        "square_commons>=1.0.0",
        "square_logger>=1.0.0",
        "square_database_helper>=2.0.0",
        "square_database_structure>=1.0.0",
        "pytest>=8.0.0",
        "httpx>=0.27.2",
    ],
    extras_require={},
    author="thePmSquare",
    author_email="thepmsquare@gmail.com",
    description="authentication layer for my personal server.",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    url=f"https://github.com/thepmsquare/{package_name}",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
    ],
)
