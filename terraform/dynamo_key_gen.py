import json
key = {'LockID': {'S': 'cms-terraform-state-prod/cms/prod/terraform.tfstate'}}
with open('dynamo_key.json', 'w') as f:
    json.dump(key, f)
print('done')
