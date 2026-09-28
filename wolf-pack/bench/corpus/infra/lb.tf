resource "aws_lb_listener" "public" {
  port       = 443
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "azurerm_storage_account" "logs" {
  min_tls_version = "TLS1_2"
  # min_tls_version = "TLS1_0"   (before the 2025 audit)
}
