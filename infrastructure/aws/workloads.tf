# Targets: lambda, eks_audit


resource "aws_iam_role" "lambda" {
  name = "${local.name}-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "archive_file" "lambda" {
  type        = "zip"
  output_path = "${path.module}/.terraform/lambda.zip"
  source {
    content  = "exports.handler = async () => ({ statusCode: 200, body: 'ventra lab' });"
    filename = "index.js"
  }
}

resource "aws_lambda_function" "lab" {
  function_name    = "${local.name}-hello"
  role             = aws_iam_role.lambda.arn
  handler          = "index.handler"
  runtime          = "nodejs20.x"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  tags             = { Name = "${local.name}-lambda" }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.lab.function_name}"
  retention_in_days = 7
}

module "eks" {
  count   = var.enable_eks ? 1 : 0
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "${local.name}-eks"
  cluster_version = "1.31"

  vpc_id     = aws_vpc.lab.id
  subnet_ids = aws_subnet.private[*].id

  enable_cluster_creator_admin_permissions = true

  eks_managed_node_groups = {
    default = {
      instance_types = ["t3.small"]
      min_size       = 1
      max_size       = 2
      desired_size   = 1
    }
  }

  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  tags = { Name = "${local.name}-eks" }
}
