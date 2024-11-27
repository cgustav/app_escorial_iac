# Network Configuration
aws_region = "us-east-1"
vpc_cidr   = "10.0.0.0/16"

public_subnet_cidrs = {
  "us-east-1a" = "10.0.1.0/24"
  "us-east-1b" = "10.0.2.0/24"
}

private_subnet_cidrs = {
  "us-east-1a" = "10.0.3.0/24"
  "us-east-1b" = "10.0.4.0/24"
}

# Instance Configuration
instance_type = "t2.micro"
ami_id        = "ami-0c7217cdde317cfec"

# Domain Configuration
domain_name      = "yourdomainhere.com"
subdomain        = "yourdomainhere"
route53_zone_id  = "Z1014814XJMZCMGK15ZI"

# Database Configuration
db_config = {
  name            = "YOUR_DB_NAME_HERE"
  username        = "YOUR_USERNAME_HERE"          # Cambiar en producción
  password        = "YOUR_DB_PASSWORD_HERE"      # Cambiar en producción
  instance_class  = "db.t3.micro"
  engine          = "mysql"
  engine_version  = "8.0"
  port            = "3306"
}

# S3 Configuration
s3_bucket_name = "escorial-images-btrgn99"

# Auto Scaling Configuration
asg_config = {
  min_size         = 1
  max_size         = 4
  desired_capacity = 1
}
 
# GitHub Deploy Key (Considerar mover a AWS Secrets Manager)
github_deploy_key = <<-EOT
    -----BEGIN OPENSSH PRIVATE KEY-----
    YOUR PRIVATE KEY HERE
    -----END OPENSSH PRIVATE KEY-----
EOT

# Tags Configuration
default_tags = {
  Environment = "staging"
  Project     = "django-escorial"
  ManagedBy   = "terraform"
}