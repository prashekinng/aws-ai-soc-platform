resource "aws_security_group" "sg" {
  for_each = var.customers
  name = "cms-${each.key}-sg"
  description = "Allow inbound HTTP traffic for CMS"
  vpc_id = aws_vpc.customer[each.key].id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cms-${each.key}-sg"
    project = var.project
  }
}

##security group for the splunk ec2
resource "aws_security_group" "splunk" {
  name = "cms-splunk-sg"
  description = "Allow splunk UI access"
  vpc_id = aws_vpc.splunk.id

  ingress {
    description = "splunk web UI access"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cms-splunk-sg"
    project = var.project
  }
}