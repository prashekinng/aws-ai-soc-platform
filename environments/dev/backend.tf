bucket         = "cms-terraform-state-dev"
key            = "cms/dev/terraform.tfstate"
region         = "ap-south-1"
dynamodb_table = "cms-terraform-locks-dev"
use_lockfile = true
encrypt        = true