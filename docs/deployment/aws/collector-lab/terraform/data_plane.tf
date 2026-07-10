resource "aws_kms_key" "lab" {
  description             = "Ventra collector lab CMK"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = { Collector = "kms" }
}

resource "aws_kms_alias" "lab" {
  name          = "alias/${var.project}"
  target_key_id = aws_kms_key.lab.key_id
}

resource "aws_secretsmanager_secret" "db_creds" {
  name = "${var.project}/dbadmin/credentials"
  tags = {
    Collector = "secrets"
    Story     = "leaked-db-creds"
  }
}

resource "aws_secretsmanager_secret_version" "db_creds" {
  secret_id = aws_secretsmanager_secret.db_creds.id
  secret_string = jsonencode({
    username = "dbadmin"
    password = "CHANGE-ME-lab-only"
    host     = aws_db_instance.lab.address
    database = aws_db_instance.lab.db_name
  })
}

resource "aws_db_subnet_group" "lab" {
  name       = "${var.project}-db"
  subnet_ids = [for s in aws_subnet.private : s.id]
  tags       = { Collector = "rds" }
}

resource "aws_security_group" "rds" {
  name        = "${var.project}-rds"
  description = "RDS for collector lab"
  vpc_id      = aws_vpc.lab.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "lab" {
  identifier                 = "${var.project}-postgres"
  engine                     = "postgres"
  engine_version             = "16.4"
  instance_class             = "db.t4g.micro"
  allocated_storage          = 20
  db_name                    = "ventralab"
  username                   = "ventraadmin"
  manage_master_user_password = true
  db_subnet_group_name       = aws_db_subnet_group.lab.name
  vpc_security_group_ids     = [aws_security_group.rds.id]
  skip_final_snapshot        = true
  backup_retention_period    = 1
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  tags = {
    Collector = "rds"
    Story     = "database-tier"
  }
}

resource "aws_iam_role" "eks_cluster" {
  count = var.enable_eks ? 1 : 0
  name  = "${var.project}-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  count      = var.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_cluster[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_nodes" {
  count = var.enable_eks ? 1 : 0
  name  = "${var.project}-eks-nodes"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_nodes_worker" {
  count      = var.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_nodes_cni" {
  count      = var.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_nodes_ecr" {
  count      = var.enable_eks ? 1 : 0
  role       = aws_iam_role.eks_nodes[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_eks_cluster" "lab" {
  count    = var.enable_eks ? 1 : 0
  name     = "${var.project}-eks"
  role_arn = aws_iam_role.eks_cluster[0].arn
  version  = "1.31"

  vpc_config {
    subnet_ids = [for s in aws_subnet.private : s.id]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  tags = { Collector = "eks_audit" }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster,
  ]
}

resource "aws_eks_node_group" "lab" {
  count           = var.enable_eks ? 1 : 0
  cluster_name    = aws_eks_cluster.lab[0].name
  node_group_name = "${var.project}-nodes"
  node_role_arn   = aws_iam_role.eks_nodes[0].arn
  subnet_ids      = [for s in aws_subnet.private : s.id]

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }

  instance_types = ["t3.small"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_nodes_worker,
    aws_iam_role_policy_attachment.eks_nodes_cni,
    aws_iam_role_policy_attachment.eks_nodes_ecr,
  ]
}
