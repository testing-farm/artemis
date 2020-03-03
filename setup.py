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
            'artemis-init-sqlite-schema = artemis.db:init_sqlite',
            'artemis-init-postgres-schema = artemis.db:init_postgres'
        ]
    },

    install_requires=[
        'ansible-vault==1.2.0',
        'awscli==1.16.298',
        'beaker-client==27.0',
        'beautifulsoup4',
        'dataclasses==0.6',
        'dramatiq[rabbitmq, watch]',
        'gluetool==1.20',
        'gunicorn==19.9.0',
        'molten==0.7.4',
        'psycopg2==2.8.4',
        'sqlalchemy',
        'stackprinter',
        'python-openstackclient==5.0.0'
    ],

    author='tft',
    author_email='',
    description='',
    license='',
    keywords='',
    url='',
    long_description=''
)
