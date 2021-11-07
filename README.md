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

1. create security group

2. create instance role for ssm agent

3. event watcher to run ssm run command to setup a drual site using composer and drush

4. change the database password to a secure version in parameter store or secrets manager

5. add load balancer

6. add RDS 

7. add EFS

8. add ElastiCache memcachd

9. create VPC with public and private subnets