# variables.tf

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "availability_zones" {
  description = "Availability zones in the region"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = map(string)
  default = {
    "us-east-1a" = "10.0.1.0/24"
    "us-east-1b" = "10.0.2.0/24"
  }
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = map(string)
  default = {
    "us-east-1a" = "10.0.3.0/24"
    "us-east-1b" = "10.0.4.0/24"
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "ami_id" {
  description = "AMI ID for EC2 instances"
  type        = string
  default     = "ami-0c7217cdde317cfec"
}

variable "domain_name" {
  description = "Domain name for the application"
  type        = string
  default     = "mydomain.com"
}

variable "subdomain" {
  description = "Subdomain for the application"
  type        = string
  default     = "mydomain"
}

variable "route53_zone_id" {
  description = "Route53 hosted zone ID"
  type        = string
  default     = "Z10XXXXXXXXXXXX"
}

variable "route53_target_domain" {
  description = "Route53 subdomain to expose ALB"
  type        = string
  default     = "app.mydomain.com"
}

variable "acm_certificate_config" {
  description = "ACM Ceritificate Configuration"
  type        = map(any)
  default = {
    domain_name          = "mydomain.com"
    validation_method    = "DNS"
    subject_alt_names    = ["*.mydomain.com"] 
  }
}

variable "db_config" {
  description = "Database Configuration"
  type        = map(string)
  default = {
    name            = "db_name"
    username        = "administrator"
    password        = "administrator"  # Consider using SSM Parameter Store or Secrets Manager
    instance_class  = "db.t3.micro"
    engine          = "mysql"
    engine_version  = "8.0"
    port            = "3306"
  }
}

variable "s3_bucket_name" {
  description = "Name of S3 bucket for Django images"
  type        = string
  default     = "escorial-image-bucket-xxxxx"
}

variable "asg_config" {
  description = "Auto Scaling Group configuration"
  type        = map(number)
  default = {
    min_size         = 1
    max_size         = 4
    desired_capacity = 1
  }
}

variable "github_ssh_address" {
    description = "Github SSH address to pull changes"
    type = string
    default = "git@github.com:cgustav/app_escorial.git"
}

variable "github_deploy_key" {
  description = "GitHub deploy key for repository access"
  type        = string
  default     = <<-EOT
    -----BEGIN OPENSSH PRIVATE KEY-----
    PASTE YOUR PRIVATE KEY HERE
    -----END OPENSSH PRIVATE KEY-----
  EOT
}

variable "default_tags" {
  description = "Default resource tags for infrastructure"
  type        = map(string)
  default = {
    Environment     = "development"
    Project         = "django-escorial"
    ManagedBy       = "terraform"
  }
}
