# One image for the edge, the VPN gateways (IPsec and WireGuard) and the CA, on AWS, Azure and GCP.
# Services start only when their configuration exists (/etc/pqcsuite/edge.toml, site.toml, wireguard.toml, or a CA in /var/lib/pqcsuite/pki).
#   packer init deploy/packer && packer build -only 'amazon-ebs.pqcsuite' deploy/packer
packer {
  required_plugins {
    amazon        = { source = "github.com/hashicorp/amazon", version = ">= 1.3.0" }
    azure         = { source = "github.com/hashicorp/azure", version = ">= 2.1.0" }
    googlecompute = { source = "github.com/hashicorp/googlecompute", version = ">= 1.1.0" }
  }
}

variable "version" {
  type    = string
  default = "0.3.1"
}
variable "aws_region" {
  type    = string
  default = "eu-central-1"
}
variable "azure_subscription_id" {
  type    = string
  default = ""
}
variable "azure_resource_group" {
  type    = string
  default = "pqcsuite-images"
}
variable "azure_location" {
  type    = string
  default = "westeurope"
}
variable "gcp_project" {
  type    = string
  default = ""
}
variable "gcp_zone" {
  type    = string
  default = "europe-west3-a"
}

locals {
  name = "pqcsuite-${replace(var.version, ".", "-")}-${formatdate("YYYYMMDDhhmm", timestamp())}"
}

source "amazon-ebs" "pqcsuite" {
  region        = var.aws_region
  instance_type = "t3.small"
  ssh_username  = "admin"
  ami_name      = local.name
  source_ami_filter {
    owners      = ["136693071363"]
    most_recent = true
    filters = {
      name                = "debian-13-amd64-*"
      virtualization-type = "hvm"
    }
  }
  imds_support = "v2.0"
  tags         = { Name = local.name, Product = "pqcsuite", Version = var.version }
}

source "azure-arm" "pqcsuite" {
  subscription_id                   = var.azure_subscription_id
  use_azure_cli_auth                = true
  managed_image_name                = local.name
  managed_image_resource_group_name = var.azure_resource_group
  location                          = var.azure_location
  vm_size                           = "Standard_B2s"
  os_type                           = "Linux"
  image_publisher                   = "Debian"
  image_offer                       = "debian-13"
  image_sku                         = "13-gen2"
  ssh_username                      = "packer"
}

source "googlecompute" "pqcsuite" {
  project_id          = var.gcp_project
  zone                = var.gcp_zone
  machine_type        = "e2-small"
  source_image_family = "debian-13"
  ssh_username        = "packer"
  image_name          = local.name
  image_family        = "pqcsuite"
}

build {
  sources = ["source.amazon-ebs.pqcsuite", "source.azure-arm.pqcsuite", "source.googlecompute.pqcsuite"]

  provisioner "shell" {
    inline = ["mkdir -p /tmp/pqcsuite"]
  }
  provisioner "file" {
    sources     = ["${path.root}/../../pyproject.toml", "${path.root}/../../README.md", "${path.root}/../../pqcsuite", "${path.root}/../../deploy"]
    destination = "/tmp/pqcsuite/"
  }
  provisioner "shell" {
    script = "${path.root}/provision.sh"
  }
}
