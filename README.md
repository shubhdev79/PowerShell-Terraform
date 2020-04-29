# PowerShell-Terraform
Demo Repo Created to Use Powershell to Run Terraform Configurations

**Execution in Local:**

**Go to the Path+++++++**

\Bob-Demo> powershell -ExecutionPolicy -File .\Terraform-Gen-AWS-Example.ps1

**It will take the Code of Terraform-Gen-AWS-Example.ps1 with the Help of Included Library i.**
#Include library++++++++
. "Helpers\TerraformGen-Lib.ps1";

**Outputting the Terraform File+++++**

-> $terraform_directory = "$CurrentPath\Output\$platform_name";
-> $Terraform | Out-File "$terraform_directory\main.tf" -encoding ascii;


**Terraform Init+++++**

> Write-Host "Initiating Terraform Init" -ForegroundColor Green;
    cd $terraform_directory;
    terraform init; 

**Terraform plan+++++**

> cd $terraform_directory
terraform plan -out=tfplan
