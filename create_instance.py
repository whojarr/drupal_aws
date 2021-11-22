#!/usr/bin/env python

import sys
import ec2

args = sys.argv[1:]
instance_name = None

if len(args) > 0:
    instance_name = sys.argv[1]

if instance_name == None:
    instance_name = "drupal9"

instance = ec2.DrupalServer()
instance.name = instance_name
print("Created new Drupal Instance Object:{}".format(instance))
 
instance_id = instance.create()
print("Created new EC2 Instance ID:{}".format(instance_id))
