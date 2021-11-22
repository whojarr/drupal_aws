#!/usr/bin/env python

import sys
import ec2

args = sys.argv[1:]
instance_id = None

if len(args) > 0:
    instance_id = sys.argv[1]

if instance_id == None:
    print("require an instance id as an argument")
    exit(1)

print("instance id = {}".format(instance_id))
instance = ec2.DrupalServer(instance_id=instance_id)
print(instance.instance_id)
print(instance.instance_state)
instance.terminate()
print(instance.instance_state)