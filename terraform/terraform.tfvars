region  = "ap-south-1"
project = "cms-project-terraform"

customers = {
  "garda" = {
    vpc_key     = "garda"
    vpc_cidr    = "10.3.0.0/16"
    subnet_cidr = "10.3.0.0/24"
  }
  "NYUL" = {
    vpc_key     = "NYUL"
    vpc_cidr    = "10.4.0.0/16"
    subnet_cidr = "10.4.0.0/24"
  }
}
