terraform {
    required_version = ">= 1.0" #mandates cli version to be higher than 1.0 
    required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0" #restricts pluggin versions to be greater than 5.0
    }
  }

  backend "s3" {
    bucket = "cms-terraform-state-prashanth" 
    key    = "cms/state-file.tfstate"
    region = "ap-south-1"
    dynamodb_table = "cms-terraform-locks"
    encrypt = true
  }
}


