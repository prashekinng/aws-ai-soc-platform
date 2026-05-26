# data source to fetch latest AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}


# Define the EC2 Instance
resource "aws_instance" "customer_ec2" {
  for_each = var.customers
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  subnet_id = aws_subnet.public[each.key].id
  vpc_security_group_ids = [aws_security_group.sg[each.key].id]
  iam_instance_profile = aws_iam_instance_profile.customer_profile[each.key].name
  root_block_device {
    encrypted  = true
    kms_key_id = aws_kms_key.cms.arn
  }

  tags = {
    Name = "cms-${each.key}-ec2"
    project = var.project
  }
}

#assigning an EIP to customer ec2s
resource "aws_eip" "customer_eip" {
  for_each = var.customers
  instance = aws_instance.customer_ec2[each.key].id

  tags = {
    Name = "cms-${each.key}-eip"
    project = var.project
  }
}


