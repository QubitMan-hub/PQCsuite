resource "aws_kms_key" "signing" {
  description              = "Release signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
}

resource "aws_kms_key" "data" {
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  # customer_master_key_spec = "RSA_4096"  (the old key, retired)
}

resource "google_kms_crypto_key" "tokens" {
  name     = "tokens"
  key_ring = google_kms_key_ring.main.id
  purpose  = "ASYMMETRIC_SIGN"
  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }
}

resource "azurerm_key_vault_key" "wrap" {
  name         = "wrap"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA-HSM"
  key_size     = 3072
  key_opts     = ["wrapKey", "unwrapKey"]
}
