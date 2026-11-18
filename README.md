# Security Alert Enrichment

## Overview

This project receives security alerts through an Azure HTTP-triggered Function and enriches their IP addresses using an external reputation API.

The project consists of:

### Python Enruchment Function
Validates incoming alert data, cleans IP addresses, performs reputation lookups and handles rate limits, timeouts and API failures. The logic is independent of Azure and is tested in test_enrichment.py

### Function App
The Azure Function App provides the HTTP endpoint that receives security alerts and passes them to the Python enrichment logic. It returns the enriched results to the caller.


### Terraform 
For this project, terraform was used to define the Azure resource group, storage account, Function App, Key Vault, managed identity, Key Vault role assignment and Application Insights for monitoring. Terraform formatting and validation were checked locally and the infrastructure has not been applied to Azure.

### GitHub Actions WorkFlow:
Runs code and infrastructure checks and defines the deployment pipeline. The workflow performs Python linting and formatting, pytest, Terraform formatting and validation, and Gitleaks secret scanning on pull requests targeting main. On pushes to main, it attempts to create a Terraform plan, apply it after approval, and deploy the Function.


## Project Structure

- `function_app.py` – Azure HTTP-triggered Function.
- `enrichment.py` – Alert validation, IP cleanup, rate limiting, API lookups, verdict calculation, enrichment.
- `test_enrichment.py` – Automated tests for enrichment logic using mocked HTTP requests.
- `terraform/` – Infrastructure definitions.
- `.github/workflows/ci.yml` – CI and deployment pipeline.




## Run Locally

### Requirements

- Python 3.11
- Azure Functions Core Tools
- Dependencies listed in `requirements.txt`


### Install dependencies:
```
pip install -r requirements.txt
```

### Set the reputation API key as an environment variable in PowerShell:
```
$env:REPUTATION_API_KEY="your-api-key"
```

### Start the Azure Function locally:

```powershell
func start --python
```

### The endpoint is:

`POST http://localhost:7071/api/alert-triage`

where an alert is sent to locally run Function.


### Run Tests

```powershell
py -3.11 -m pytest -v
```
The tests mock external HTTP requests, so they do not require a real API key, newtwork access, or make requests to the reputation service.


## Terraform State

Terraform state is configured to use an Azure Storage backend. The storage account and blob container for the state file must exist before running terraform init.

The placeholder backend values in terraform/main.tf must be replaced with the actual storage account, container and state file details.

Azure Blob Storage provides state locking through blob leases, helping prevent concurrent Terraform operations from changing the same infrastructure state.

Access to the state storage account should be restricted to authorised deployment identities and administrators. Storage security features such as encryption, versioning and soft delete should be enabled to help protect and recover state.


## Pipeline Authentication - Azure and Github Actions

The deployment workflow uses OpenID Connect (OIDC) through azure/login@v2. This avoids storing a long-lived Azure client secret in GitHub.

To enable deployment, an Azure application registration or service principal must be configured with a federated identity credential that trusts the GitHub repository and the relevant branch or GitHub environment. It must also have the Azure permissions needed to manage the Terraform resources and deploy the Function App.

The following GitHub repository variables are required:

- AZURE_CLIENT_ID

- AZURE_TENANT_ID

- AZURE_SUBSCRIPTION_ID

- AZURE_FUNCTIONAPP_NAME



## Role of Function Identity:

Function App uses a system-assigned managed identity which has the Key Vault Secrets User role assigned to it so it can read the reputation API key from Key Vault.


Why this role?
- The Function needs to retrieve the reputation API key.
- It only needs permission to read secrets.
- It does not need permission to create, change or delete secrets.
This follows the principle of least privilege: giveing the application only the permissions it needs.


## Idempotency (How to prevent the same alert being processed twice)

To prevent the same alert from being processed more than once, Store each `alert_id` in persistent storage to keep track of processed alert IDs.

Before processing an alert, the function would check whether its `alert_id` has already been processed.

- If it has, the function would return the previously stored result instead of processing it again.
- If it has not, the function would process the alert and store the result using the `alert_id` as a unique key.

A unique constraint would prevent two identical alerts arriving simultaneously from being processed twice.

Persistent storage is not implemented in this work


## Failure Detection (To know if this automation silently stopped working)
Application Insights is included for application monitoring. In a production deployment, it should be used to review Function execution logs, exceptions and failed requests.

Alerts shoulcan d be configured for Function failures, unexpected increases in failed requests and missing expected activity. This helps identify situations where the Function stops processing alerts without someone noticing.


## Further Improvements

With more time, persistent idempotency storage can be added, monitoring alerts configure, and test the complete deployment process in an Azure environment. 

### Use of AI Assistance

AI assistance was used to help explain unfamiliar concepts, review some implementation decisions, and troubleshoot issues. The code, tests and configuration were also reviewed and validated as part of the development process.





