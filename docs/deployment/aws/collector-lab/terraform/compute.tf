data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "web" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = values(aws_subnet.private)[0].id
  vpc_security_group_ids = [aws_security_group.web.id]
  user_data = <<-EOF
              #!/bin/bash
              dnf install -y httpd
              cat > /var/www/html/index.html <<'HTML'
              <html><body><h1>Ventra Lab Web App</h1><a href="/admin-panel">Admin</a></body></html>
              HTML
              mkdir -p /var/www/html/admin-panel
              echo '<html><body><h1>Admin Panel</h1></body></html>' > /var/www/html/admin-panel/index.html
              systemctl enable --now httpd
              EOF
  tags = {
    Name      = "${var.project}-web"
    Collector = "ec2"
    Story     = "web-tier"
  }
}

resource "aws_ebs_snapshot" "lab" {
  volume_id = aws_instance.web.root_block_device[0].volume_id
  tags = {
    Name      = "${var.project}-web-root-snap"
    Collector = "ec2"
    Story     = "snapshot-exfil-target"
  }
}

resource "aws_lb" "lab" {
  name               = "${var.project}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [for s in aws_subnet.public : s.id]
  tags               = { Collector = "elb_alb" }

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb"
    enabled = true
  }
}

resource "aws_lb_target_group" "web" {
  name     = "${var.project}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.lab.id
  health_check {
    path = "/"
  }
}

resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = aws_lb_target_group.web.arn
  target_id        = aws_instance.web.id
  port             = 80
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.lab.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

resource "aws_cloudfront_distribution" "lab" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Ventra collector lab CDN fronting ALB"
  default_root_object = "index.html"

  origin {
    domain_name = aws_lb.lab.dns_name
    origin_id   = "alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    forwarded_values {
      query_string = true
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = { Collector = "cloudfront" }
}
