from setuptools import setup


setup(
    name='artemis',
    version='0.0.1',
    package_dir={
        'artemis': 'artemis'
    },
    packages=[
        'artemis',
        'artemis.api',
        'artemis.drivers'
    ],
    entry_points={
        'console_scripts': [
            'artemis-api-server = artemis.api:main',
            'artemis-dispatcher = artemis.dispatcher:main',
            'artemis-init-sqlite-schema = artemis.db:init_sqlite'
        ]
    },

    install_requires=[
        'ansible-vault==1.2.0',
        'awscli==1.16.298',
        'dataclasses==0.6',
        'dramatiq[rabbitmq, watch]',
        'gluetool==1.19.1',
        'gunicorn==19.9.0',
        'molten==0.7.4',
        'apache-libcloud==2.6.0',
        'paramiko==2.6.0',
        'sqlalchemy',
        'stackprinter'
    ],

    author='tft',
    author_email='',
    description='',
    license='',
    keywords='',
    url='',
    long_description=''
)
