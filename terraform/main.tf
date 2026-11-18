
# Create the Azure resource group
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    environment = var.environment
  }
}

# Create the storage account used by the Function App
resource "azurerm_storage_account" "main" {
  name                     = var.storage_account_name
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    environment = var.environment
  }
}

# Create the hosting plan for the Linux Function App
resource "azurerm_service_plan" "main" {
  name                = var.service_plan_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "Y1"

  tags = {
    environment = var.environment
  }
}

# Create Application Insights to monitor the Function App
resource "azurerm_application_insights" "main" {
  name                = var.app_insights_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  application_type    = "web"

  tags = {
    environment = var.environment
  }
}

# Create Key Vault to securely store the reputation API key
resource "azurerm_key_vault" "main" {
  name                = var.key_vault_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true

  tags = {
    environment = var.environment
  }
}

# Create the Linux Function App that runs the Python enrichment code
resource "azurerm_linux_function_app" "main" {
  name                = var.function_app_name
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  service_plan_id            = azurerm_service_plan.main.id
  storage_account_name       = azurerm_storage_account.main.name
  storage_account_access_key = azurerm_storage_account.main.primary_access_key

  functions_extension_version = "~4"
  https_only                  = true

  # Assign a system-managed identity to the Function App
  identity {
    type = "SystemAssigned"
  }

  # Configure the Python runtime
  site_config {
    application_stack {
      python_version = "3.11"
    }
  }

  # Configure the Function App's environment settings
  app_settings = {
    "REPUTATION_API_KEY"                    = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault.main.vault_uri}secrets/${var.key_vault_secret_name}/)"
    "APPLICATIONINSIGHTS_CONNECTION_STRING" = azurerm_application_insights.main.connection_string
    "FUNCTIONS_WORKER_RUNTIME"              = "python"
    "AzureWebJobsStorage"                   = azurerm_storage_account.main.primary_connection_string
  }

  tags = {
    environment = var.environment
  }
}

# Give the Function App permission to read secrets from Key Vault
resource "azurerm_role_assignment" "function_key_vault" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_function_app.main.identity[0].principal_id
}
