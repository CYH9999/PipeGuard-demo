# BasraShop deploy role: trust policy narrowed by PipeGuard (python -m pipeguard fix).

resource "aws_iam_role" "basrashop_deploy" {
  name               = "basrashop-deploy"
  assume_role_policy = data.aws_iam_policy_document.pipeguard_basrashop_deploy.json
}
