import ec2

security_group = ec2.DrupalSecurityGroup()
print("Created new Drupal Security Group Object:{}".format(security_group))

if security_group.exists():
    print("Security Group Exists")
    exit(1)

security_group_id = security_group.create()
print("Created new EC2 Security Group ID:{}".format(security_group_id))
