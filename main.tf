# main.tf

provider "aws" {
  region = "us-east-1"
  default_tags {
        tags = var.default_tags
  }
}

# VPC y Networking
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge({
    Name = "django-vpc"
  })
}

# Subnets públicas en diferentes AZs
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[var.availability_zones[0]]
  availability_zone       = var.availability_zones[0]

  map_public_ip_on_launch = true

  tags = merge({
    Name = "django-public-subnet-1",
    AccessLevel = "public"
  })
}

resource "aws_subnet" "public_2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[var.availability_zones[1]]
  availability_zone = var.availability_zones[1]


  map_public_ip_on_launch = true

  tags = merge({
    Name = "django-public-subnet-2",
    AccessLevel = "public"
  })
}

# Subnet privada para RDS
resource "aws_subnet" "private_1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[var.availability_zones[0]]
  availability_zone = var.availability_zones[0]


  tags = merge({
    Name = "django-private-subnet-1",
    AccessLevel = "private"
  })
}

resource "aws_subnet" "private_2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[var.availability_zones[1]]
  availability_zone = var.availability_zones[1]

  tags = merge({
    Name = "django-private-subnet-2",
    AccessLevel = "private"
  })
}

# Asociaciones de tablas de rutas para las subnets públicas
resource "aws_route_table_association" "public_1" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_2" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public.id
}

# Asociaciones de tablas de rutas para las subnets privadas
resource "aws_route_table_association" "private_1" {
  subnet_id      = aws_subnet.private_1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_2" {
  subnet_id      = aws_subnet.private_2.id
  route_table_id = aws_route_table.private.id
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge({
    Name = "django-igw"
  })
}

# NAT Gateway para la subred privada
resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_1.id  # Cambiado de public a public_1


  tags = merge({
    Name = "django-nat"
  })
}

# Tablas de rutas
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge({
    Name = "django-public-rt"
  })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = merge({
    Name = "django-private-rt"
  })
}

# Grupo de seguridad para EC2
resource "aws_security_group" "ec2" {
  name        = "django-ec2-sg"
  description = "Security group for Django EC2 instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

#   ingress {
#     from_port       = 8000
#     to_port         = 8000
#     protocol        = "tcp"
#     security_groups = [aws_security_group.alb.id]
#   }

  # NOTE - Nginx expone servicio en el 80 / 8000 ya no es necesario
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Grupo de seguridad para RDS
resource "aws_security_group" "rds" {
  name        = "django-rds-sg"
  description = "Security group for Django RDS instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  tags = merge({
    Name = "django-rds-sg",
    AccessLevel = "private"
  })
}

# Grupo de seguridad para ALB
resource "aws_security_group" "alb" {
  name        = "django-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ENABLE SSL OVER TCP/IP
  ingress {
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
}

# IAM Role y Profile para las instancias
resource "aws_iam_role" "django_role" {
  name = "django_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy para EC2
resource "aws_iam_role_policy" "django_s3_access" {
  name = "django_s3_access"
  role = aws_iam_role.django_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.django_images.arn,
          "${aws_s3_bucket.django_images.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_logs" {
  name = "cloudwatch_logs"
  role = aws_iam_role.django_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}


resource "aws_iam_instance_profile" "django_profile" {
  name = "django_profile"
  role = aws_iam_role.django_role.name
}

# Launch Template para las instancias Django
resource "aws_launch_template" "django" {
  name_prefix   = var.ami_id
  image_id      = var.ami_id  # Ubuntu AMI
  instance_type = var.instance_type

  network_interfaces {
    associate_public_ip_address = true
    security_groups            = [aws_security_group.ec2.id]
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.django_profile.name
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge({
      Name = "django-asg-instance"
    })
  }

  lifecycle {
    create_before_destroy = true
  }

  # User data script
  user_data = base64encode(<<-EOF
    #!/bin/bash

    # Prevent dpkg-preconfigure: unable to re-open stdin
    export DEBIAN_FRONTEND=noninteractive

    # Actualizar el sistema
    apt-get update
    apt-get install -y python3-pip python3-dev libmysqlclient-dev gcc nginx git python3-venv build-essential pkg-config

    # Configurar el directorio para la aplicación
    mkdir -p /var/www/django
    cd /var/www/django

    # Configurar SSH para Github
    mkdir -p /root/.ssh
    cat <<-EOT > /root/.ssh/deploy_key
    ${var.github_deploy_key}
    EOT

    chmod 600 /root/.ssh/deploy_key

    # Configurar SSH para usar esta llave específica con GitHub
    cat <<-EOT > /root/.ssh/config
    Host github.com
      IdentityFile /root/.ssh/deploy_key
      StrictHostKeyChecking no
    EOT

    chmod 600 /root/.ssh/config

    # Configurar known_hosts para Github
    ssh-keyscan github.com >> /root/.ssh/known_hosts

    # Clonar el repositorio
    git clone ${var.github_ssh_address} .

    # Obtener la IP privada de la instancia
    PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

    # Obtener host y puerto por separado del endpoint de RDS
    DB_ENDPOINT="${aws_db_instance.django.endpoint}"
    
    # Quitar puerto 3306 de la variable
    DB_HOST=$(echo $DB_ENDPOINT | cut -d':' -f1)
    DB_PORT=${aws_db_instance.django.port}

    # Configurar variables de entorno
    cat <<-EOT > /var/www/django/.env
    DEBUG=False
    ALLOWED_HOSTS=${aws_lb.django.dns_name},$PRIVATE_IP,${data.aws_route53_zone.selected.name},*.${data.aws_route53_zone.selected.name}
    DJANGO_ENVIRONMENT=production
    DB_ENGINE=django.db.backends.mysql
    DB_NAME=${aws_db_instance.django.db_name}
    DB_USER=${aws_db_instance.django.username}
    DB_PASSWORD=${aws_db_instance.django.password}
    DB_HOST=$DB_HOST
    DB_PORT=3306
    DB_OPTIONS_INIT_COMMAND="SET sql_mode='STRICT_ALL_TABLES'"
    DB_OPTIONS_CHARSET=utf8mb4
    AWS_STORAGE_BUCKET_NAME=${aws_s3_bucket.django_images.id}
    AWS_S3_REGION_NAME=${data.aws_region.current.name}
    AWS_S3_FILE_OVERWRITE=False
    AWS_DEFAULT_ACL=None
    DEFAULT_FILE_STORAGE=storages.backends.s3boto3.S3Boto3Storage
    EOT

    # Crear y activar entorno virtual
    python3 -m venv /var/www/django/venv
    source /var/www/django/venv/bin/activate

    # Install WSGI for Python
    # pip3 install django unicorn
    pip3 install django gunicorn psycopg2-binary python-dotenv

    # Install Pip deps
    pip3 install -r dependencias.txt

    python3 manage.py makemigrations
    python3 manage.py migrate

    # Configurar staticfiles para django
    mkdir -p /var/www/django/staticfiles

    python3 manage.py collectstatic
    chown -R www-data:www-data /var/www/django/staticfiles
    chmod -R 755 /var/www/django/staticfiles

    # Configurar Nginx
    cat <<-EOT > /etc/nginx/sites-available/django
    server {
        listen 80;
        server_name ${aws_route53_record.django.name};

        location = /favicon.ico { access_log off; log_not_found off; }
        location /static/ {
            alias /var/www/django/staticfiles/;
        }

        location / {
            include proxy_params;
            proxy_pass http://unix:/var/www/django/app.sock;
        }
    }
    EOT

    # Habilitar sitio nginx
    rm -f /etc/nginx/sites-enabled/default
    ln -s /etc/nginx/sites-available/django /etc/nginx/sites-enabled
    
    nginx -t
    systemctl reload nginx

    # Configurar Gunicorn como servicio systemd
    #touch /var/www/django/app.sock

    cat <<-EOT > /etc/systemd/system/gunicorn.service
    [Unit]
    Description=Gunicorn daemon
    After=network.target

    [Service]
    User=www-data
    Group=www-data
    WorkingDirectory=/var/www/django
    ExecStart=/var/www/django/venv/bin/gunicorn \
        --workers 3 \
        --bind unix:/var/www/django/app.sock \
        NegocioModel.wsgi:application

    [Install]
    WantedBy=multi-user.target
    EOT

    # Iniciar servicios
    systemctl daemon-reload
    systemctl start gunicorn
    systemctl enable gunicorn

    # Permisos
    # sudo chown -R ubuntu:www-data /var/www/django/
    #sudo chmod -R g+w /var/www/django/

    chown -R www-data:www-data /var/www/django/
    chmod -R 755 /var/www/django/

    chown -R www-data:www-data /etc/nginx/sites-available/
    chmod -R 755 /etc/nginx/sites-available/

    systemctl restart gunicorn
    systemctl restart nginx

    EOF
  )

  tags = merge({
    Name = "django-server"
  })
}


# Auto Scaling Group
resource "aws_autoscaling_group" "django" {
  name                      = "django-asg"
  desired_capacity          = 1
  max_size                  = 4
  min_size                  = 1
  target_group_arns         = [aws_lb_target_group.django.arn]
  vpc_zone_identifier       = [aws_subnet.public_1.id, aws_subnet.public_2.id]
  health_check_grace_period = 300
  health_check_type         = "ELB"

  launch_template {
    id      = aws_launch_template.django.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "django-asg-instance"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Políticas de Auto Scaling
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "django-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.django.name
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "django-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.django.name
}

# CloudWatch Alarms para Auto Scaling
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "django-high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "70"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.django.name
  }

  alarm_description = "This metric monitors EC2 CPU utilization"
  alarm_actions     = [aws_autoscaling_policy.scale_up.arn]
}

resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "django-low-cpu"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "30"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.django.name
  }

  alarm_description = "This metric monitors EC2 CPU utilization"
  alarm_actions     = [aws_autoscaling_policy.scale_down.arn]
}

# Key Pair para SSH
resource "aws_key_pair" "deployer" {
  key_name   = "django-deployer-key"
  public_key = file("~/.ssh/id_rsa.pub")  # Asegúrate de tener tu llave pública aquí
}

# RDS Instance
resource "aws_db_instance" "django" {
  identifier        = "django-db"
  engine            = var.db_config["engine"]
  engine_version    = var.db_config["engine_version"]
  instance_class    = var.db_config["instance_class"]
  db_name           = var.db_config["name"]
  username          = var.db_config["username"]
  password          = var.db_config["password"]
  port              = var.db_config["port"]

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.django.name
  parameter_group_name   = aws_db_parameter_group.django.name

  skip_final_snapshot = true

  tags = merge({
    Name = "django-db",
    AccessLevel = "private"
  })

}


# Grupo de parámetros para RDS MySQL
resource "aws_db_parameter_group" "django" {
  family = "${var.db_config["engine"]}${var.db_config["engine_version"]}"
  name   = "el-escorial-params"

  parameter {
    name  = "character_set_server"
    value = "utf8mb4"
  }

  parameter {
    name  = "character_set_client"
    value = "utf8mb4"
  }

  parameter {
    name  = "sql_mode"
    value = "STRICT_ALL_TABLES"
  }

  tags = merge({
    Name = "django-db-params"
  })
}

# Subnet group para RDS
resource "aws_db_subnet_group" "django" {
  name       = "django-db-subnet-group"
  subnet_ids = [aws_subnet.private_1.id, aws_subnet.private_2.id]

}

# Application Load Balancer
resource "aws_lb" "django" {
  name               = "django-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]

}


# Generar un sufijo único
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# ALB Target Group
resource "aws_lb_target_group" "django" {
  name     = "django-tg-${random_string.suffix.result}"
  port = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health/"
    port                = "traffic-port"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = merge({
    Name = "django-target-group"
  })
}

# HTTP default redirecto to HTTPS via 443
resource "aws_lb_listener" "front_end_http" {
  load_balancer_arn = aws_lb.django.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# HTTPS Listener
resource "aws_lb_listener" "front_end_https" {
  load_balancer_arn = aws_lb.django.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.django.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.django.arn
  }

  depends_on = [aws_acm_certificate_validation.django]
}

# AWS Region Data
data "aws_region" "current" {}

# Route53 Zone (asume que ya tienes una zona hospedada)
data "aws_route53_zone" "selected" {
  zone_id = var.route53_zone_id 
}

# Route53 Record
resource "aws_route53_record" "django" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = var.route53_target_domain  # Reemplaza con tu subdominio deseado
  type    = "A"

  alias {
    name                   = aws_lb.django.dns_name
    zone_id                = aws_lb.django.zone_id
    evaluate_target_health = true
  }
}

# ACM Certificate
resource "aws_acm_certificate" "django" {
  domain_name               = var.acm_certificate_config["domain_name"]
  validation_method         = var.acm_certificate_config["validation_method"]
  subject_alternative_names = var.acm_certificate_config["subject_alt_names"]

  tags = merge({
    Name = "django-cert"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Validación DNS del certificado
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.django.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.selected.zone_id
}

# Esperar a que el certificado sea validado
resource "aws_acm_certificate_validation" "django" {
  certificate_arn         = aws_acm_certificate.django.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# S3 Bucket para imágenes
resource "aws_s3_bucket" "django_images" {
  bucket = var.s3_bucket_name

  tags = merge({
    Name = "django-images"
  })
}

# Deshabilitar el bloqueo de acceso público
resource "aws_s3_bucket_public_access_block" "django_images" {
  bucket = aws_s3_bucket.django_images.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Configuración de CORS para el bucket
resource "aws_s3_bucket_cors_configuration" "django_images" {
  bucket = aws_s3_bucket.django_images.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "POST", "PUT", "DELETE"]
    allowed_origins = [
      "https://${aws_route53_record.django.name}",
      "https://*.${data.aws_route53_zone.selected.name}"
    ]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# Política del bucket
resource "aws_s3_bucket_policy" "django_images" {
  bucket = aws_s3_bucket.django_images.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.django_images.arn}/*"
      }
    ]
  })
}


# Output para el nombre del bucket
output "s3_bucket_name" {
  value = aws_s3_bucket.django_images.id
  description = "Name of the S3 bucket for Django images"
}

# Outputs actualizados
output "alb_dns_name" {
  value = aws_lb.django.dns_name
  description = "DNS name of the Application Load Balancer"
}

output "rds_endpoint" {
  value = aws_db_instance.django.endpoint
  description = "Endpoint of the RDS instance"
}

output "asg_name" {
  value = aws_autoscaling_group.django.name
  description = "Name of the Auto Scaling Group"
}

# Opcional: Output para obtener las IPs de las instancias (necesitarás consultarlo después de la creación)
output "instance_ips" {
  value = "Use: aws ec2 describe-instances --filters 'Name=tag:Name,Values=django-asg-instance' --query 'Reservations[].Instances[].PublicIpAddress'"
  description = "Command to get the IPs of the ASG instances"
}

output "domain_name" {
    value = data.aws_route53_zone.selected.name
    description = "Domain name used for the application."
}

output "certificate_arn" {
    value = aws_acm_certificate.django.arn
    description = "ARN of the SSL certificate"
}