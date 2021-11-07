import ec2

instance = ec2.DrupalServer()
print("Created new Drupal Instance Object:{}".format(instance))
 
instance_id = instance.create()
print("Created new EC2 Instance ID:{}".format(instance_id))
