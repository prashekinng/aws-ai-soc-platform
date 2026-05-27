
# 1. data source to fetch latest splunk AMI
data "aws_ami" "ubuntu_2204" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_instance" "splunk_ec2" {
  ami                    = data.aws_ami.ubuntu_2204.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.splunk.id
  vpc_security_group_ids = [aws_security_group.splunk.id]
  iam_instance_profile   = aws_iam_instance_profile.splunk_profile.name

  root_block_device {
    encrypted  = true
    kms_key_id = aws_kms_key.cms.arn
  }

  user_data = base64encode(<<EOF
#!/bin/bash
snap install amazon-ssm-agent --classic
systemctl start snap.amazon-ssm-agent.amazon-ssm-agent.service
systemctl enable snap.amazon-ssm-agent.amazon-ssm-agent.service
EOF
  )

  tags = {
    Name    = "cms-splunk-ec2"
    project = var.project
  }
}

# Create the EBS Volume
resource "aws_ebs_volume" "splunk_volume" {
  availability_zone = "ap-south-1a"
  size              = 20
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.cms.arn
  lifecycle {
  prevent_destroy = true
  }

  tags = {
    Name = "cms-splunk-data"
    project = var.project
  }
}

# Attach the Volume to the Instance
resource "aws_volume_attachment" "splunk_att" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.splunk_volume.id
  instance_id = aws_instance.splunk_ec2.id

}

# 3. assigning an EIP to customer ec2s
resource "aws_eip" "splunk_eip" {
  instance = aws_instance.splunk_ec2.id

  tags = {
    Name = "cms-splunk-eip"
    project = var.project
  }
}
