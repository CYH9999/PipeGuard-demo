# PipeGuard fixture repo: basrashop_critical (infra/main.tf)
# Weakness: the deploy role trusts GitHub's OIDC provider and checks only aud: no sub
#           condition, so a workflow in ANY repository on github.com can assume it.
#           The workflow needs only repo:acme/site:ref:refs/heads/main (final demo repo).

resource "aws_iam_role" "basrashop_deploy" {
  name = "basrashop-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}
