variable "region" {
  description = "The AWS region to deploy resources into"
  type        = string
}

variable "project" {
  description = "project name"
  type        = string
}

variable "customers" {
  description = "customers list"
  type        = map(object({
    vpc_key     = string
    vpc_cidr    = string
    subnet_cidr = string
  }))
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for GuardDuty alerts"
  type        = string
  sensitive   = true
}