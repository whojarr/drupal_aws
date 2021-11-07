#/usr/bin/python

import ec2

instance = ec2.DrupalServer()
print(instance)
 
instance_id = instance.create()
print(instance_id)

# instance = ec2.DrupalServer(instance_id="i-09438f0850c6b6a30")
# print(instance.instance_id)
# print(instance.instance_state)
# instance.terminate()
# print(instance.instance_state)