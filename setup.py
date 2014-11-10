#!/usr/bin/env python

from setuptools import setup, find_packages

requires = []

setup(name='pynode',
      version='0.1',
      description='A second iteration of pynode',
      classifiers=[
          "Programming Language :: Python",
      ],
      keywords='bitcoin',
      packages=find_packages(),
      zip_safe=False,
      install_requires=requires,
      entry_points={
          'console_scripts': [
              'pynode = pynode.node:main'
          ]
      }
      )
