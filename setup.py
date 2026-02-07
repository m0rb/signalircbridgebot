from setuptools import setup

setup(
    name="signalbridgebot",
    version="0.1.0",
    description="Bridge messages between Signal contacts/groups and an IRC channel",
    py_modules=["signalbridgebot"],
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9,<4",
        "irc>=20.0,<21",
    ],
    entry_points={
        "console_scripts": [
            "signalbridgebot=signalbridgebot:main",
        ],
    },
)
