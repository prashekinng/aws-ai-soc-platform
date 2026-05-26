resource "aws_vpc" "customer" {
  for_each = var.customers
  cidr_block       = each.value.vpc_cidr
  tags = {
    Name = "cms-${each.key}-vpc"
    project = var.project
  }
}

resource "aws_subnet" "public" {
  for_each = var.customers
  vpc_id                  = aws_vpc.customer[each.key].id
  cidr_block              = each.value.subnet_cidr
  map_public_ip_on_launch = true
  tags = {
    Name = "cms-${each.key}-subnet"
    project = var.project
  }
}

resource "aws_internet_gateway" "igw" {
  for_each = var.customers
  vpc_id = aws_vpc.customer[each.key].id
  tags = {
    Name = "cms-${each.key}-igw"
    project = var.project
  }
}

resource "aws_route_table" "public_rt" {
  for_each = var.customers
  vpc_id = aws_vpc.customer[each.key].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw[each.key].id
  }
  tags = {
    Name = "cms-${each.key}-rt"
    project = var.project
  }
}


resource "aws_route_table_association" "public_rta" {
  for_each = var.customers
  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public_rt[each.key].id
}


##VPC and networking details for SPLUNK ec2.

resource "aws_vpc" "splunk" {
  cidr_block       = "10.0.0.0/16"
  tags = {
    Name = "cms-splunk-vpc"
    project = var.project
  }
}

resource "aws_subnet" "splunk" {
  vpc_id                  = aws_vpc.splunk.id
  cidr_block              = "10.0.0.0/24"
  availability_zone       = "ap-south-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "cms-splunk-subnet"
    project = var.project
  }
}

resource "aws_internet_gateway" "splunk" {
  vpc_id = aws_vpc.splunk.id
  tags = {
    Name = "cms-splunk-igw"
    project = var.project
  }
}

resource "aws_route_table" "splunk" {
  vpc_id = aws_vpc.splunk.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.splunk.id
  }
  tags = {
    Name = "cms-splunk-rt"
    project = var.project
  }
}

resource "aws_route_table_association" "splunk" {
  subnet_id      = aws_subnet.splunk.id
  route_table_id = aws_route_table.splunk.id
}
