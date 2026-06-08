bucket         = "cms-terraform-state-prod"
key            = "cms/prod/terraform.tfstate"
region         = "ap-south-1"
dynamodb_table = "cms-terraform-locks-prod"
use_lockfile = true
encrypt        = true