# drupal aws automation tasks

A collection of command lines (soon rest apis) to manage drupal instances on AWS AMI2

<https://github.com/whojarr/drupla_aws/>

Contact: David Hunter dhunter@digitalcreation.co.nz

Copyright (C) 2021 Digital Creation Ltd

For license information, see LICENSE

## Requires

serverless framework <https://www.serverless.com/>

yarn <https://classic.yarnpkg.com/en/>

python 3.8 (i use pyenv below to meet this requirement)

poetry <https://python-poetry.org/>

pyenv <https://github.com/pyenv/pyenv> (option to use the version in .python-version automatically)

## setup

```poetry install```

```poetry shell```

## command lines

### create instance

```./create_instance.py```

creates a new instance running mariadb, php and apache with composer installed

### list instances

```./list_instances.py```

list all drupal instance created with the tag: {"Product": "drupal"}

### terminate instance

```./terminate_intance.py {instance id}```

terminates an existing instance

## TODO

* create instance role for ssm agent

* change the database password to a secure version in parameter store or secrets manager

* add load balancer

* add RDS

* add EFS

* add ElastiCache memcachd

* add s3 and cdn module

* create VPC with public and private subnets

## references

<https://github.com/aws-quickstart/quickstart-drupal/>
