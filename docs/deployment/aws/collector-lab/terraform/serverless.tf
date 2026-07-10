resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project}-processor"
  retention_in_days = 14
  tags              = { Collector = "lambda_logs" }
}

resource "aws_lambda_function" "processor" {
  function_name = "${var.project}-processor"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 30

  filename         = "${path.module}/../assets/lambda_processor.zip"
  source_code_hash = filebase64sha256("${path.module}/../assets/lambda_processor.zip")

  tags = { Collector = "lambda" }
}

resource "aws_api_gateway_rest_api" "lab" {
  name        = "${var.project}-api"
  description = "Ventra collector lab REST API"
  tags        = { Collector = "apigateway" }
}

resource "aws_api_gateway_resource" "admin" {
  rest_api_id = aws_api_gateway_rest_api.lab.id
  parent_id   = aws_api_gateway_rest_api.lab.root_resource_id
  path_part   = "admin"
}

resource "aws_api_gateway_method" "admin_get" {
  rest_api_id   = aws_api_gateway_rest_api.lab.id
  resource_id   = aws_api_gateway_resource.admin.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "admin_lambda" {
  rest_api_id             = aws_api_gateway_rest_api.lab.id
  resource_id             = aws_api_gateway_resource.admin.id
  http_method             = aws_api_gateway_method.admin_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.processor.invoke_arn
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.lab.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "lab" {
  rest_api_id = aws_api_gateway_rest_api.lab.id
  depends_on  = [aws_api_gateway_integration.admin_lambda]
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.lab.id
  deployment_id = aws_api_gateway_deployment.lab.id
  stage_name    = "prod"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw.arn
    format = jsonencode({
      requestId    = "$context.requestId"
      ip           = "$context.identity.sourceIp"
      caller       = "$context.identity.caller"
      httpMethod   = "$context.httpMethod"
      resourcePath = "$context.resourcePath"
      status       = "$context.status"
    })
  }

  tags = { Collector = "apigateway" }
}

resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/${var.project}/apigateway/prod"
  retention_in_days = 14
}

resource "aws_api_gateway_account" "lab" {
  cloudwatch_role_arn = aws_iam_role.apigw_logs.arn
}

resource "aws_iam_role" "apigw_logs" {
  name = "${var.project}-apigw-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "apigateway.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "apigw_logs" {
  name = "${var.project}-apigw-logs"
  role = aws_iam_role.apigw_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents",
        "logs:GetLogEvents",
        "logs:FilterLogEvents"
      ]
      Resource = "*"
    }]
  })
}
