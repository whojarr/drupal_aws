#!/usr/bin/env python

import ec2
import json

instances = ec2.instance_list(product="drupal")
response = json.dumps(instances, indent=4)
print("Found the following ec2 instances:{}".format(response))
