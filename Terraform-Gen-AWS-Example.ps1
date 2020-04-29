# Change into root folder
if ($BasePath -ne $null) { cd $BasePath };
$CurrentPath = (Get-Location).Path;
if ((Test-Path "$CurrentPath\Helpers") -eq $false) { Write-Warning "Change into correct folder. Ctrl-C to break"; pause; } else { $BasePath = $CurrentPath }

# Include library
. "Helpers\TerraformGen-Lib.ps1";

# Global Config
$provider = 'aws'; # AWS/GCP
$region = 'us-east-1';
$platform_name = "ex1"; # A prefix to use in AWS naming

#cd $terraform_directory

# Networking Config
$vpc_cidr_prefix = "10.0.9";
$vpc_cidr = "$vpc_cidr_prefix.0/24";

# Subnet Config.  CIDRs to refer to instances.  
# I think this can eventually go away, as exactly how a subnet is split isn't important, only whether it's private or public
# Even private or public could potentially/eventually go away and stored further behind in the template of the server type (ex. DBMS is always private)
$vpc_cidr_public1 = "$vpc_cidr_prefix.0/27";
$vpc_cidr_public2 = "$vpc_cidr_prefix.32/27";
$vpc_cidr_private1 = "$vpc_cidr_prefix.64/26";
$vpc_cidr_private2 = "$vpc_cidr_prefix.128/26";
$vpc_cidr_mgmt1 = "$vpc_cidr_prefix.192/27";
$vpc_cidr_mgmt2 = "$vpc_cidr_prefix.224/27";

$tags = $null; # Common tags to tag AWS entities
$aws_keyname = "CISO"; # AWS key name.  Must exist in AWS account

###########################################
# Sets the Terraform default provider
$Terraform = provider $provider -region $region;

# Create VPC
$Terraform += provider_vpc `
                -provider $provider <# AWS/GCP. Determines which function to run to generate terraform #> `
                -id "$platform_name-vpc1" <# Terraform ID to refer back to when linking #> `
                -platform_name $platform_name <# Used for naming/organizing objects in AWS according to a prefix #> `
                -vpc_cidr $vpc_cidr <# CIDR for the entire VPC #> `
                -tags $tags <# Common tags #> `
                -bool_igw $true; <# Boolean to add an Internet Gateway, which has a separate Terraform block #>

# Create Subnet
$Terraform += provider_subnet `
                -provider $provider <# AWS/GCP. Determines which function to run to generate terraform #> `
                -id "$platform_name-public1" <# Terraform ID to refer back to when linking #> `
                -name "$platform_name Public 1" <# Name tag to set in AWS #> `
                -vpc_id "$platform_name-vpc1" <# Terraform ID to match provider_vpc.id above #> `
                -cidr_block $vpc_cidr_public1 `
                -region $region `
                -az_letter "a" `
                -tags $tags `
                -bool_public_ip $false; <# Boolean to auto assign a public IP to instances in subnet #>

# Create Security Group
# The idea would be to make generating new environments lightweight, so I think some of the ingress/egress rules should be hidden to the
#   end user although they will also need the ability to add customer specific ingress/egress.  If this can be done here great, otherwise
#   we could get the end user to manually add those to the generated Terraform.
$ingress = @( 
    @{ "from_port"="3389"; "to_port"="3389"; "protocol"="tcp"; "cidr"="47.55.127.100/32" };
    @{ "from_port"="0"; "to_port"="0"; "protocol"="-1"; "cidr"=$vpc_cidr };
    @{ "from_port"="3389"; "to_port"="3389"; "protocol"="tcp"; "cidr"="172.16.0.0/16" };
)
$egress = @( 
    @{ "from_port"="0"; "to_port"="0"; "protocol"="-1"; "cidr"=$vpc_cidr };
    @{ "from_port"="0"; "to_port"="0"; "protocol"="-1"; "cidr"="10.0.0.0/16" };
    @{ "from_port"="0"; "to_port"="0"; "protocol"="-1"; "cidr"="0.0.0.0/0" };
)
$Terraform += aws_security_group `
                -id "$platform_name-sg1" `
                -name "$platform_name-sg1" `
                -vpc_id "$platform_name-vpc1" `
                -ingress $ingress `
                -egress $egress `
                -tags $tags

# Possibly roll into aws_instance($kms_object)
$kms_key_id = "kms_ebs_key1";
$Terraform += aws_kms_key -id "$kms_key_id" -name "$kms_key_id" -enable_key_rotation "true" -tags $tags;
$Terraform += aws_kms_alias -id ("$kms_key_id" + "_alias") -name ("alias/$kms_key_id" + "_alias") -key_id $kms_key_id;

$s_id = "$platform_name-dc1";
$Terraform += aws_instance -id "$s_id" -name "$s_id" `
                -ami "ami-08bf5f54919fada4a" `
                -instance_type "t2.large" `
                -subnet_id "$platform_name-public1" `
                -iam_instance_profile $null `
                -disable_api_termination "false" `
                -ebs_optimized "false" `
                -private_ip "$vpc_cidr_prefix.10" `
                -key_name $aws_keyname `
                -source_dest_check "false" `
                -vpc_security_group_id "$platform_name-sg1" `
                -tags $tags `
                -root_block_device_volume_type "gp2" `
                -root_block_device_volume_size "30" `
                -delete_on_termination "true" `
                -bool_elastic_ip $true;

# Attach snapshot to the server.  Could be rolled into aws_instance() based on server type to determine if attaching is required
#$Terraform += aws_ebs_volume -id "windows_sxs" -name "windows_sxs" -encrypted "true" -kms_key_id "kms_ebs_key1" -snapshot_id $Windows_SXS_Snapshot.SnapshotId -az "aws_instance.$s_id.availability_zone" -type "gp2" -tags $tags;
#$Terraform += aws_volume_attachment -id "windows_sxs_a" -device_name "xvde" -volume_id "windows_sxs" -instance_id "$s_id";

# Location to output Terraform files
$terraform_directory = "$CurrentPath\Output\$platform_name";
if ((Test-Path $terraform_directory) -eq $false) {
    mkdir $terraform_directory > $null;
    $TerraformInit = $true;
}

$Terraform | Out-File "$terraform_directory\main.tf" -encoding ascii;

if ($TerraformInit -eq $true) {
    Write-Host "Initiating Terraform Init" -ForegroundColor Green;
    cd $terraform_directory;
    terraform init;
    cd $BasePath;
    $TerraformInit = $false;
}

cd $terraform_directory
terraform plan -out=tfplan
#terraform apply tfplan