# 1. define role
resource "aws_iam_role" "customer" {
  for_each = var.customers
  name     = "cms-${each.key}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "cms-${each.key}-role"
    project = var.project
  }
}

# 2. define policy and attach policy to role
locals {
  customer_managed_policies = {
    ssm = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    cw  = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
    ecr = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  }

  customer_policy_attachments = {
    for pair in setproduct(keys(var.customers), keys(local.customer_managed_policies)) :
    "${pair[0]}-${pair[1]}" => {
      customer = pair[0]
      policy   = local.customer_managed_policies[pair[1]]
    }
  }
}

resource "aws_iam_role_policy_attachment" "customer" {
  for_each   = local.customer_policy_attachments
  role       = aws_iam_role.customer[each.value.customer].name
  policy_arn = each.value.policy
}


# 3. Create the Instance Profile and link it to the Role
resource "aws_iam_instance_profile" "customer_profile" {
  for_each = var.customers
  name = "cms-${each.key}-profile"
  role = aws_iam_role.customer[each.key].name
}


#############################################################
#splunk ec2 roles and policies association.

# 1. define role
resource "aws_iam_role" "splunk" {
  name     = "splunk-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "splunk-role"
    project = var.project
  }
}


#2 define policy and attachment to role
resource "aws_iam_role_policy_attachment" "splunk" {
  # Convert a list of ARNs to a set for for_each
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonGuardDutyReadOnlyAccess",
    "arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess",
    "arn:aws:iam::aws:policy/AWSConfigReadOnlyAccess"
  ])

  role       = aws_iam_role.splunk.name
  policy_arn = each.value
}


# 3. Create the Instance Profile and link it to the Role
resource "aws_iam_instance_profile" "splunk_profile" {
  name = "splunk-profile"
  role = aws_iam_role.splunk.name
}


############################################################
# IAM role for AWS Config.

# 1. define role
resource "aws_iam_role" "config" {
  name     = "config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "config-role"
    project = var.project
  }
}


#2 define policy and attachment to role
resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}


##################################################################
# IAM for VPC flow logs

# 1. define role
resource "aws_iam_role" "vpc_flow_logs" {
  name     = "vpc_flow_logs_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "vpc-flow-logs.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "vpc_flow_logs_role"
    project = var.project
  }
}


#2 define custom inline policy
resource "aws_iam_role_policy" "vpc_flow_logs_policy" {
  name = "vpcflowlogs_inline_policy"
  role = aws_iam_role.vpc_flow_logs.id

  # Use jsonencode to ensure valid JSON syntax
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
          "logs:CreateLogGroup", 
          "logs:CreateLogStream", 
          "logs:PutLogEvents", 
          "logs:DescribeLogGroups", 
          "logs:DescribeLogStreams"
        ]
        
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

