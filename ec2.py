import boto3

class DrupalSecurityGroup(object):
    '''
    class to create a drupal ec2 security group
    '''
    def __init__(self, security_group_id=None, name="drupal9_security_group", region="ap-southeast-2"):
        '''
        Constructor
        '''
        self.security_group_id = security_group_id
        self.name = name
        self.region = region


    def create(self):
        pass



    def exists(self):
        '''
        look for a security group with the tags Name:drupal9_security_group Product:Drupal Version:9
        '''
        
        return True


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
        self.user_data = '''#!/bin/bash
yum update -y
amazon-linux-extras install -y php7.3
amazon-linux-extras install -y mariadb10.5
yum install -y httpd mariadb-server git php-xml php-gd php-mbstring mod_ssl httpd-itk

sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

systemctl start httpd
systemctl enable httpd
cd /etc/pki/tls/certs
./make-dummy-cert localhost.crt
cd ~
sed -i -e 's/SSLCertificateKeyFile/#SSLCertificateKeyFile/g' /etc/httpd/conf.d/ssl.conf
sed -i -e 's/LoadModule mpm_prefork_module/#LoadModule mpm_prefork_module/g' /etc/httpd/conf.modules.d/00-mpm.conf
sed -i -e 's/#LoadModule mpm_event_module/LoadModule mpm_event_module/g' /etc/httpd/conf.modules.d/00-mpm.conf
systemctl stop httpd
systemctl start httpd

cd /var/www/html/
wget https://files.phpmyadmin.net/phpMyAdmin/5.1.1/phpMyAdmin-5.1.1-all-languages.zip
unzip phpMyAdmin-5.1.1-all-languages.zip
mv phpMyAdmin-5.1.1-all-languages phpMyAdmin
cd ~

usermod -a -G apache ec2-user
chown -R ec2-user:apache /var/www
chmod 2775 /var/www

find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;

systemctl start mariadb
systemctl enable mariadb

mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'CHANGEME';"
mysql -e "DROP DATABASE IF EXISTS test"
mysql -e "FLUSH PRIVILEGES"

systemctl stop mariadb
systemctl start mariadb

curl -sS https://getcomposer.org/installer | sudo php
mv composer.phar /usr/local/bin/composer
ln -s /usr/local/bin/composer /usr/bin/composer

'''


    def create(self):

        instances = self.ec2_client.run_instances(
            ImageId=self.image_id,
            MinCount=1,
            MaxCount=1,
            InstanceType=self.instance_type,
            SecurityGroupIds=['sg-09e6e6998361f67c3'],
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
