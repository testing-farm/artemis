from setuptools import setup


setup(
    name='artemis',
    version='0.0.1',
    package_dir={
        'artemis': 'artemis'
    },
    packages=[
        'artemis'
    ],
    entry_points={
        'console_scripts': [
            'artemis-server = artemis:main'
        ]
    },

    install_requires=[
        'ansible-vault==1.2.0',
        'dataclasses==0.6',
        'gluetool==1.19.1',
        'apache-libcloud==2.6.0',
        'paramiko==2.6.0'
    ],

    author='tft',
    author_email='',
    description='',
    license='',
    keywords='',
    url='',
    long_description=''
)
