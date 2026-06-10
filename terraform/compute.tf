# data source to fetch latest AMI
locals {
  customer_ami = "ami-016f910f55cb4096d"
}


# Define the EC2 Instance
resource "aws_instance" "customer_ec2" {
  for_each = var.customers
  ami           = local.customer_ami
  instance_type = "t3.micro"
  subnet_id = aws_subnet.public[each.key].id
  vpc_security_group_ids = [aws_security_group.sg[each.key].id]
  iam_instance_profile = aws_iam_instance_profile.customer_profile[each.key].name
  root_block_device {
    encrypted  = true
    kms_key_id = aws_kms_key.cms.arn
  }

  tags = {
  Name     = "cms-${each.key}-ec2"
  Customer = each.key
  project  = var.project
  }
}



