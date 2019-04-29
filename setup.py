#!/usr/bin/env python3
"""gcp_audit project setup."""
import sys
import subprocess
import shlex
from pathlib import Path
from typing import List
from setuptools import setup, find_packages  # type: ignore
from setuptools.command.develop import develop  # type: ignore
from pip.req import parse_requirements  # type: ignore


def parse_reqs(requirements_file: str) -> List[str]:
    """Get requirements as a list of strings from the file."""
    return [
        str(r.req) for r in parse_requirements(requirements_file, session=False)
        if r.req is not None
    ]

class CustomDevelop(develop):
    """Develop command that actually prepares the development environment."""

    def run(self):
        """Setup the local dev environment fully."""
        super().run()

        for command in [
            'pip install -U pip',
            'pip install -r dev_requirements.txt'
        ]:
            print('\nCustom develop - executing:', command, file=sys.stderr)
            subprocess.check_call(shlex.split(command))


README_FILE = Path(__file__).resolve().with_name('README.md')
README = README_FILE.read_text('utf-8')
REQUIREMENTS = parse_reqs('requirements.txt')
TEST_REQUIREMENTS = parse_reqs('dev_requirements.txt')

setup(
    name='gcp_audit',
    version='0.0.1',
    description='Auditing tool for GCP',
    long_description=README,
    classifiers=[
        'Topic :: Office/Business :: Application',
        'License :: Other/Proprietary License',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='',
    author='Infectious Media',
    author_email='sre@infectiousmedia.com',
    license='Proprietary',
    packages=find_packages(exclude=['tests']),
    install_requires=REQUIREMENTS,
    tests_require=TEST_REQUIREMENTS,
    extras_require={'tests': TEST_REQUIREMENTS},
    cmdclass={
        'develop': CustomDevelop,
    }
)
