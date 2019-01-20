from distutils.core import setup

setup(
    name='opycanka',
    version='0.1dev',
    packages=['opycanka',],
    install_requires=[
              'pyscard',
          ],
    license='Apache License, Version 2.0',
    long_description=open('README.MD').read(),
)