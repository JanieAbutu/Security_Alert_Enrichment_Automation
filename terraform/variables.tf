variable "resource_group_name" {
  description = "Name of the Azure resource group"
  type        = string
}

variable "location" {
  description = "Azure region for the resources"
  type        = string
  default     = "westeurope"
}

variable "storage_account_name" {
  description = "Globally unique storage account name"
  type        = string
}

variable "service_plan_name" {
  description = "Name of the Function App service plan"
  type        = string
}

variable "function_app_name" {
  description = "Globally unique Function App name"
  type        = string
}

variable "app_insights_name" {
  description = "Name of the Application Insights resource"
  type        = string
}

variable "key_vault_name" {
  description = "Globally unique Key Vault name"
  type        = string
}

variable "tenant_id" {
  description = "Azure tenant ID"
  type        = string
}

variable "key_vault_secret_name" {
  description = "Name of the API key secret stored in Key Vault"
  type        = string
  default     = "ReputationApiKey"
}

variable "environment" {
  description = "Deployment environment (dev or prod)"
  type        = string

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be either dev or prod."
  }
}