# drupal aws automation tasks

## Requires

python 3.8

poetry


## setup

poetry install

poetry shell


## command lines


### create instance

python create_instance.py

creates a new instance running mariadb, php and apache with composer installed


### terminate instance

python terminate_intance.py {instance id}

terminates an existing instance


## TODO:

* create instance role for ssm agent

* event watcher to run ssm run command to setup a drual site using composer and drush

* change the database password to a secure version in parameter store or secrets manager

* add load balancer

* add RDS 

* add EFS

* add ElastiCache memcachd

* create VPC with public and private subnets