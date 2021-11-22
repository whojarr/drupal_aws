import datetime
import json
import boto3

class DrupalSecurityGroup(object):
    '''
    class to create a drupal ec2 security group
    '''
    def __init__(self, security_group_id=None, name="drupal9_security_group", region="ap-southeast-2", vpc_id=None):
        '''
        Constructor
        '''
        self.security_group_id = security_group_id
        self.name = name
        self.region = region
        self.ec2_client = boto3.client("ec2", region_name=self.region)
        self.vpc_id = vpc_id
        if not self.vpc_id:
            self.vpc_id = vpc_default()


    def create(self):

        security_group = self.ec2_client.create_security_group(
            Description = self.name,
            GroupName = self.name,
            VpcId = self.vpc_id,
            TagSpecifications=[
                {
                    'ResourceType': 'security-group',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': self.name
                        },
                        {
                            'Key': 'Product',
                            'Value': 'drupal'
                        },
                        {
                            'Key': 'Version',
                            'Value': '9'
                        }
                    ]
                }
            ]
        )

        ''' add ingress rules '''
        security_group_id = security_group['GroupId']
        self.ec2_client.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [
                        {'CidrIp': '0.0.0.0/0'}
                    ]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [
                        {'CidrIp': '0.0.0.0/0'}
                    ]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [
                        {'CidrIp': '0.0.0.0/0'}
                    ]
                }
            ]
        )

        return security_group['GroupId']


    def exists(self):
        '''
        look for a security group with the tags Name:drupal9_security_group Product:Drupal Version:9
        '''
        # list security group with tag Product: drupal
        security_groups = security_group_list(product="drupal")
        if len(security_groups['SecurityGroups']) > 0:
            return security_groups['SecurityGroups'][0]['GroupId']
        return False


class DrupalServer(object):
    '''
    class to create a drupal ec2 instance
    '''

    def __init__(self, instance_id=None, name="drupal9", image_id="ami-04a81599b183d7908", instance_type="t3.micro", region="ap-southeast-2"):
        '''
        Constructor
        '''
        self.instance_id = instance_id
        self.instance_state = None
        self.name = name
        self.image_id = image_id
        self.instance_type = instance_type
        self.region = region
        self.ec2_client = boto3.client("ec2", region_name=self.region)
        self.user_data = self.cloud_init_cmd()


        #"mysql -e \"ALTER USER 'root'@'localhost' IDENTIFIED BY 'CHANGEME';\"",
        #"mysql -e \"DROP DATABASE IF EXISTS test\"",
        #"mysql -e \"FLUSH PRIVILEGES\"",


    def drupal_apache_conf(self):

        conf = """
<VirtualHost *:80>
    ServerAdmin  dhunter@digitalcreation.co.nz
    ServerName  drupal9.pauanui.nz
    ServerAlias www.drupal9.pauanui.nz
    DocumentRoot /var/www/drupal/web
    <Directory /var/www/drupal/web>
        Options -Indexes -MultiViews +FollowSymLinks
        AllowOverride All
        Order allow,deny
        allow from all
    </Directory>
    LogLevel warn
    ErrorLog /var/log/httpd/drupal-error.log
    CustomLog /var/log/httpd/drupal-access.log combined
</VirtualHost>
ServerSignature Off
ServerTokens Prod
"""

        return conf


    def cloud_init_cmd(self):
        cmds = [
            "#!/bin/bash",
            "yum update -y",
            "amazon-linux-extras install -y php7.3",
            "amazon-linux-extras install -y mariadb10.5",
            "yum install -y httpd mariadb-server git php-cli php-common php-pdo php-mysqlnd php-xml php-gd php-mbstring php-fpm php-opcache php-pecl-memcached php-pecl-apcu mod_ssl httpd-itk",
            "sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm",
            "sudo systemctl enable amazon-ssm-agent",
            "sudo systemctl start amazon-ssm-agent",

            "systemctl start mariadb",
            "systemctl enable mariadb",


            "mysql -e \"CREATE DATABASE IF NOT EXISTS drupal9 CHARACTER SET UTF8 COLLATE utf8_general_ci;\"",
            "mysql -e \"GRANT ALL ON drupal9.* TO 'drupal'@'%' IDENTIFIED BY 'drup4lp4ssw0rd';\"",

            "cd /etc/httpd/conf.d/",
            "rm -f autoindex.conf notrace.conf userdir.conf welcome.conf",
            "echo \"" + self.drupal_apache_conf() + "\" > /etc/httpd/conf.d/drupal.conf",
            "cd ~",

            "systemctl start httpd",
            "systemctl enable httpd",
            "cd /etc/pki/tls/certs",
            "./make-dummy-cert localhost.crt",
            "cd ~",
            "sed -i -e 's/SSLCertificateKeyFile/#SSLCertificateKeyFile/g' /etc/httpd/conf.d/ssl.conf",
            "sed -i -e 's/LoadModule mpm_prefork_module/#LoadModule mpm_prefork_module/g' /etc/httpd/conf.modules.d/00-mpm.conf",
            "sed -i -e 's/#LoadModule mpm_event_module/LoadModule mpm_event_module/g' /etc/httpd/conf.modules.d/00-mpm.conf",

 
            "systemctl stop httpd",
            "systemctl start httpd",

            "cd /var/www/html/",
            "wget https://files.phpmyadmin.net/phpMyAdmin/5.1.1/phpMyAdmin-5.1.1-all-languages.zip",
            "unzip phpMyAdmin-5.1.1-all-languages.zip",
            "mv phpMyAdmin-5.1.1-all-languages phpMyAdmin",
            "cd ~",

            "usermod -a -G apache ec2-user",
            "chown -R ec2-user:apache /var/www",
            "chmod 2775 /var/www",

            "find /var/www -type d -exec chmod 2775 {} \;",
            "find /var/www -type f -exec chmod 0664 {} \;",


            "systemctl stop mariadb",
            "systemctl start mariadb",


            "export HOME=/root",
            "export DRUSH_PHP=/usr/bin/php",
            "cd /root/",
            "sed -i 's/allow_url_fopen = Off/allow_url_fopen = On/g' /etc/php.ini",
            "curl -sS https://getcomposer.org/installer | php",

            "mv composer.phar /usr/local/bin/composer",
            "ln -s /usr/local/bin/composer /usr/bin/composer",
            "/usr/bin/composer global require drush/drush:10.*",
            "/usr/bin/composer create-project drupal/recommended-project:9.* drupal",
            "sed -i 's/allow_url_fopen = On/allow_url_fopen = Off/g' /etc/php.ini",
            "sed -i 's/expose_php = On/expose_php = Off/g' /etc/php.ini",
            "sed -i 's/memory_limit = 128M/memory_limit = -1/g' /etc/php.ini",
            "cd /root/drupal",
            "/usr/bin/composer require drush/drush:^10",
            "cd /root",
            "mv /root/drupal /var/www/drupal",
            "cd /var/www/drupal",
            "/var/www/drupal/vendor/bin/drush site-install standard --yes --site-name=drupal9  --site-mail=dhunter@digitalcreation.co.nz --account-name=admin --account-pass=l3tm31n --db-url=mysql://drupal:drup4lp4ssw0rd@localhost/drupal9 --db-prefix=drupal_",
            "cd /var/www/drupal/web/sites/default",
            "echo \"\$_SERVER['HTTPS'] = 'On';\" >> settings.php",
            "chown -R ec2-user:apache /var/www/drupal",
            "chmod -R 750 /var/www/drupal",
            "chmod -R 770 /var/www/drupal/web/sites/default/files",
        ]
        result = '\n'.join(cmds)

        return result


    def create(self):

        sg = DrupalSecurityGroup()
        security_group_id = sg.exists()
        if not security_group_id:
            print("Failed to identify valid security group id")
            exit(1)
        print("Using Security Group ID:{}".format(security_group_id))

        instances = self.ec2_client.run_instances(
            ImageId=self.image_id,
            MinCount=1,
            MaxCount=1,
            InstanceType=self.instance_type,
            SecurityGroupIds=[security_group_id],
            IamInstanceProfile={
                'Arn': 'arn:aws:iam::687368024180:instance-profile/SSMInstanceProfile'
            },
            KeyName="drupal",
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': self.name
                        },
                        {
                            'Key': 'Product',
                            'Value': 'drupal'
                        },
                        {
                            'Key': 'Version',
                            'Value': '9'
                        }
                    ]
                },
                {
                    'ResourceType': 'volume',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': self.name
                        },
                        {
                            'Key': 'Product',
                            'Value': 'drupal'
                        },
                        {
                            'Key': 'Version',
                            'Value': '9'
                        }
                    ]
                },
            ],
            UserData=self.user_data
        )
        self.instance_id = instances["Instances"][0]["InstanceId"]

        return self.instance_id


    def exists(self):
        return True


    def stop(self):

        response = self.ec2_client.stop_instances(InstanceIds=[self.instance_id])
        self.instance_state = response["StoppingInstances"][0]["CurrentState"]["Name"]

        return self.instance_state


    def terminate(self):

        response = self.ec2_client.terminate_instances(InstanceIds=[self.instance_id])
        self.instance_state = response["TerminatingInstances"][0]["CurrentState"]["Name"]

        return self.instance_state


class DrupalServers(object):
    '''
    class to manage drupal instances
    '''
    def __init__(self, region="ap-southeast-2", vpc_id=None):
        '''
        Constructor
        '''
        self.region = region
        if vpc_id:
            self.vpc_id = vpc_id
        else:
            vpc_id = vpc_default()
        self.ec2_client = boto3.client("ec2", region_name=self.region)

    def list(self):
        instances = self.ec2_client.describe_vpcs()
        print(instances)


def getnametag(tags):
    name = ""
    for tag in tags:
        if tag['Key'] == 'Name':
            name = tag['Value']
    return(name)


def getenvironmenttag(tags):
    name = ""
    for tag in tags:
        if tag['Key'] == 'environment':
            name = tag['Value']
    return(name)


def instance_list(region='ap-southeast-2', environment=None, instance_state=None, product=None):

    instance_ec2 = boto3.client('ec2', region_name=region)
    instances = []
    filters = []

    if product:
        product_filter = {
                'Name': 'tag:Product',
                'Values': [
                        product
                    ]
            }
        filters.append(product_filter)

    if instance_state:
        instance_state_filter = {
                'Name': 'instance-state-name',
                'Values': [
                        instance_state
                    ]
            }
        filters.append(instance_state_filter)

    if environment:
        environment_filter = {
                'Name': 'tag:environment',
                'Values': [
                        environment
                    ]
            }
        filters.append(environment_filter)

    instances_returned = instance_ec2.describe_instances(Filters=filters)

    for reservation in instances_returned['Reservations']:
        for instance in reservation['Instances']:
            output = json.dumps(instance, indent=4, default=myconverter)
            #print(output)
            result = dict()
            result['id'] = instance['InstanceId']
            result['instance_type'] = instance['InstanceType']
            result['state'] = instance['State']['Name']
            result['state_transition_reason'] = instance['StateTransitionReason']
            result['cpu_options_core_count'] = instance['CpuOptions']['CoreCount']
            result['cpu_options_threads_per_core'] = instance['CpuOptions']['ThreadsPerCore']
            result['name'] = getnametag(instance['Tags'])
            result['environment'] = getenvironmenttag(instance['Tags'])
            if 'PublicIpAddress' in instance:
                result['public_ip'] = instance['PublicIpAddress']
            if 'PrivateIpAddress' in instance:
                result['private_ip'] = instance['PrivateIpAddress']
            result['region'] = region
            instances.append(result)

    return instances


def instance_list_filtered(region=None, environment=None, instance_state=None, product=None):
    names = []
    if region:
        names.extend(instance_list(region=region, environment=environment, instance_state=instance_state, product=product))
    else:
        for region in regions_list():
            names.extend(instance_list(region=region, environment=environment, instance_state=instance_state, product=product))
    return names


def myconverter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()


def security_group_list(vpc_id=None, product=None):

    if not vpc_id:
        vpc_id = vpc_default()

    ec2_client = boto3.client('ec2')
    filters = [
        {
            'Name': 'vpc-id',
            'Values': [
                vpc_id
            ]
        }
    ]
    if product:
        product_filter = {
            'Name': 'tag:Product',
            'Values': [
                'drupal'
            ]
        }
        filters.append(product_filter)

    security_groups = ec2_client.describe_security_groups(
        Filters=filters
    )

    return security_groups


def regions_list():
    regions = []
    ec2_client = boto3.client('ec2')
    regions_returned = ec2_client.describe_regions().get('Regions', [])
    for region in regions_returned:
        regions.append(region['RegionName'])
    return regions


def vpc_default():
    vpc_id = None
    ec2_client = boto3.client("ec2", region_name="ap-southeast-2")
    vpcs = ec2_client.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        if vpc["IsDefault"]:
            vpc_id = vpc['VpcId']

    return vpc_id