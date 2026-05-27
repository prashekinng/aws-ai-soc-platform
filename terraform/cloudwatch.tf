resource "aws_cloudwatch_log_group" "cms" {
  for_each          = local.customer_vpcs
  name              = "/cms/vpcflowlogs/${each.key}"
  retention_in_days = 30

  tags = {
    Name    = "cms-${each.key}-loggroup"
    project = var.project
  }
}
