#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'Click>=6.0',
    'python-bugzilla>=1.2.2',
    'py-trello>=0.5.0',
    'PyGithub>=1.29',
    # TODO: put package requirements here
]

test_requirements = [
    # TODO: put package test requirements here
]

setup(
    name='trilla',
    version='0.1.0',
    description="Sync bugs, trello cards and github PRs!",
    long_description=readme + '\n\n' + history,
    author="Vritant Jain",
    author_email='adarshvritant@gmail.com',
    url='https://github.com/vritant/trilla',
    packages=[
        'trilla',
    ],
    package_dir={'trilla':
                 'trilla'},
    entry_points={
        'console_scripts': [
            'trilla=trilla.cli:main'
        ]
    },
    include_package_data=True,
    install_requires=requirements,
    license="GNU General Public License v3",
    zip_safe=False,
    keywords='trilla',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements
)
