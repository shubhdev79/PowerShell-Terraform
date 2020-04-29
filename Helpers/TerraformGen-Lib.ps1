function provider($provider, $region) {
  switch($provider) {
    "aws" { aws_provider -region $region; }
    "gcp" { gcp_provider -region $region }
  }
}

function gcp_dns_zone($id, $name, $dns_name) {
  return '

resource "google_dns_managed_zone" "' + $id + '" {
  name     = "' + $name + '"
  dns_name = "' + $dns_name + '"
}'
}

function gcp_dns_record($id, $zone_id, $name, $type, $records, $ttl) {
  return '
  
resource "google_dns_record_set" "' + $id + '" {
  name = "' + $name + '"
  type = "' + $type + '"
  ttl  = ' + $ttl + '

  #managed_zone = google_dns_managed_zone.prod.name
  managed_zone = "' + $zone_id + '"

  rrdatas = [' + $records + ']
}'
}

function aws_route53_record($id, $zone_id, $name, $type, $records, $ttl) {
  return '
  
resource "aws_route53_record" "' + $id + '" {
  zone_id = "' + $zone_id + '"
  name    = "' + $name + '"
  type    = "' + $type + '"
  records = [' + $records + ']
  ttl     = ' + $ttl + '
}'
}

function aws_provider($region) {
  return '
  
provider "aws" {
  region     = "' + $region + '"
  version     = "~> 2.34.0"
}'
}
function gcp_provider($region) {
  return '
  
provider "google" {
  credentials = file("gcp.json")
  project     = "starlit-braid-272212"
  region      = "' + $region + '"
}'
}

function aws_security_group($id, $name, $vpc_id, $ingress, $egress, $tags) {
    $tf_output = '
    
resource "aws_security_group" "' + $id + '" {
  name              = "' + $name + '"
  vpc_id            = aws_vpc.' + $vpc_id + '.id'
  foreach ($rule in $ingress) {
    $tf_output += '
      ingress {
        description = "' + $rule.description + '"
        from_port   = ' + $rule.from_port + '
        to_port     = ' + $rule.to_port + '
        protocol    = "' + $rule.protocol + '"
        cidr_blocks = [ "' + $rule.cidr + '" ]
      }'
  }
  foreach ($rule in $egress) {
    $tf_output += '
      egress {
        description = "' + $rule.description + '"
        from_port   = ' + $rule.from_port + '
        to_port     = ' + $rule.to_port + '
        protocol    = "' + $rule.protocol + '"
        cidr_blocks = [ "' + $rule.cidr + '" ]
      }'
  }
  
  $tf_output += '
  tags = merge(
    map(
      "Name", "' + $name + '"
    ), ' + $tags + '
  )'
  $tf_output += '
  
}'
  return $tf_output;
}

function aws_kms_key ($id, $name, $enable_key_rotation, $tags) {
  return '
  
resource "aws_kms_key" "' + $id + '" {
  description             = "EBS key for ' + $name + '"
  enable_key_rotation     = ' + $enable_key_rotation + '
  tags = merge(
    map(
      "Name", "' + $name + '",
    ), ' + $tags + '
  )
}'
}

function aws_kms_alias ($id, $name, $key_id) {
  return '

resource "aws_kms_alias" "' + $id + '" {
  name                    = "' + $name + '"
  target_key_id           = aws_kms_key.' + $key_id + '.id
}
'
}

function aws_ebs_volume ($id, $name, $encrypted, $kms_key_id, $az, $size, $type, $tags, $snapshot_id) {
  $tf_output = '

resource "aws_ebs_volume" "' + $id + '" {
  availability_zone = ' + $az + '
  type              = "' + $type + '"
  '
  if ($snapshot_id -ne $null) {
    $tf_output += 'snapshot_id       = "' + $snapshot_id + '"
    '
  }
  else {
    $tf_output += 'size              = "' + $size + '"
    '
  }

  if ($encrypted -eq $true) {
    $tf_output += 'encrypted         = true
      kms_key_id        = aws_kms_key.' + $kms_key_id + '.arn
    '
  }

  $tf_output += 'tags = merge(
    map(
      "Name", "' + $name + '",
    ), ' + $tags + '
  )
}'
  return $tf_output;
}

function aws_volume_attachment ($id, $device_name, $volume_id, $instance_id) {
  return '

resource "aws_volume_attachment" "' + $id + '" {
  device_name = "' + $device_name + '"
  volume_id   = aws_ebs_volume.' + $volume_id + '.id
  instance_id = aws_instance.' + $instance_id + '.id
}'
}
function aws_instance($id, $name, $ami, $instance_type, $subnet_id, $iam_instance_profile, $disable_api_termination, $ebs_optimized, $private_ip, $key_name, $source_dest_check,
  $vpc_security_group_id, $user_data, $user_data_script, $tags, $root_block_device_volume_type, $root_block_device_volume_size, $delete_on_termination,
  $bool_elastic_ip) {

  $tf_output = '
  
resource "aws_instance" "' + $id + '" {
  ami                     = "' + $ami + '"
  instance_type           = "' + $instance_type + '"
  subnet_id               = aws_subnet.' + $subnet_id + '.id'
  if ($iam_instance_profile -ne $null) { 
    $tf_output += '
    iam_instance_profile    = "' + $iam_instance_profile + '"'
  }
  $tf_output += '
  disable_api_termination = "' + $disable_api_termination + '"
  ebs_optimized           = "' + $ebs_optimized + '"
  private_ip              = "' + $private_ip + '"
  key_name                = "' + $key_name + '"
  source_dest_check       = "' + $source_dest_check + '"
  vpc_security_group_ids  = [ aws_security_group.' + $vpc_security_group_id + '.id ]'
  if ($user_data_script -ne $null) {
    #$user_data = (gc $user_data_script).Replace('"','""');
    $full_user_data = gc $user_data_script;
    $full_user_data = "<powershell>" + $full_user_data; # + "</powershell>"
    if ($user_data -ne $null) {
      $full_user_data += $user_data + "</powershell>";
    }
    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($full_user_data);
    $EncodedText =[Convert]::ToBase64String($Bytes);

    $tf_output += '
    user_data_base64 = "' + $EncodedText + '"'
  }
  $tf_output += '
  #user_data               = "' + $user_data + '"
  lifecycle {
    ignore_changes = [user_data, user_data_base64]
  }
  '
  $tf_output += '
  tags = merge(
    map(
      "Name", "' + $name + '"
    ), ' + $tags + '
  )'
  $tf_output += '
  root_block_device {
    volume_type = "' + $root_block_device_volume_type + '"
    volume_size = "' + $root_block_device_volume_size + '"
    delete_on_termination = ' + $delete_on_termination + '
  }
}
'
  if ($bool_elastic_ip -eq $true) {
    $tf_output += aws_eip -id "$id-eip" -name $name -tags $tags -instance_id $id;
  }

  return $tf_output;
}

function gcp_forwarding_rule($id, $name, $region, $load_balancing_scheme, $backend_service, $all_ports, $allow_global_access, $network) {
  return '

resource "google_compute_forwarding_rule" "' + $id + '" {
  name                  = "' + $name + '"
  region                = "' + $region + '"
  load_balancing_scheme = "' + $load_balancing_scheme + '"
  backend_service       = google_compute_region_backend_service.' + $backend_service + '.self_link
  all_ports             = ' + $all_ports + '
  allow_global_access   = ' + $allow_global_access + '
  network               = google_compute_network.' + $network + '.name
}'
}

function gcp_firewall($id, $name, $ingress_range, $vpc_id) {
  $tf_output = "";
  $tf_output += '
  
resource "google_compute_firewall" "' + $id + '" {
  name    = "' + $name + '"
  network = google_compute_network.' + $vpc_id + '.name

  allow {
    protocol = "icmp"
  }

  source_ranges = [ '
  foreach ($entry in $ingress_range) {
    $tf_output += '"' + $entry + '", ';
  }
  $tf_output += ' ]

  allow {
    protocol = "tcp"
    ports    = ["1-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["1-65535"]
  }

  source_tags = ["web"]
}'
  return $tf_output;
}

function gcp_route ($id, $name, $dest_cidr, $vpc_id) {
  return '
  
  resource "google_compute_route" "' + $id + '" {
  name        = "' + $name + '"
  dest_range  = "' + $dest_cidr + '"
  network     = google_compute_network.' + $vpc_id + '.name
  next_hop_network = "projects/starlit-braid-272212/global/networks/tt1-vpc"
  priority    = 100
}'
}
function gcp_instance($id, $name, $instance_type, $region, $az_letter, $ami_name, $subnet_id, $ip_address, $secondary_ip_cidrs, $windows_startup_script_url, $tags, $secondary_disk_size) {
  $name = $name.tolower();
  $name = $name.replace(' ','-');
  #$user_data = $user_data.replace('"',"'")
  $tf_output = "";

  if ($secondary_disk_size -ne $null) {
    $tf_output += '  
resource "google_compute_disk" "' + $id + '-wfo" {
  name  = "' + $id + '-wfo"
  type  = "pd-ssd"
  zone  = "' + ($region + '-' + $az_letter) + '"
  labels = {
    environment = "dev"
  }
  size = ' + $secondary_disk_size + '
  physical_block_size_bytes = 4096
}
'
  }
  $tf_output += '
  
resource "google_compute_instance" "' + $id + '" {
  name         = "' + $name + '"
  machine_type = "' + $instance_type + '"
  zone         = "' + ($region + '-' + $az_letter) + '"
  tags = [' + ($tags | % { ('"' + $_ + '",') }) + ']
  boot_disk {
    initialize_params {
      image = "' + $ami_name + '"
    }
  }
  '

  if ($secondary_disk_size -ne $null) {
    $tf_output += '
  depends_on = [
    google_compute_disk.' + $id + '-wfo
  ]

  attached_disk {
    source = "' + $id + '-wfo"
  }
  '
  }

  $tf_output += '
  network_interface {
    #network = google_compute_network.vpc1.self_link
    subnetwork = google_compute_subnetwork.' + $subnet_id + '.self_link
    '
    if ($ip_address -ne $null) {
      $tf_output += 'network_ip = "' + $ip_address + '"
      '
    }
    
    if ($secondary_ip_cidrs -ne $null) {
      foreach ($cidr in $secondary_ip_cidrs) {
        $tf_output += '
        alias_ip_range {
          ip_cidr_range = "' + $cidr + '"
        }';
      }

          #$tf_output += '"' + $cidr + '",';
        #};
        #$tf_output += '"127.0.0.1/32"]';

        #$secondary_ip_cidrs | % { $tf_output += '"' + $_ + '",' };
      #$tf_output += '  
      #}'
    }

    $tf_output += '
    access_config {
      // Ephemeral IP
    }
  }

  metadata = {
    windows-startup-script-url = "' + $windows_startup_script_url + '"
  }
}
'
  return $tf_output;
}
#windows-startup-script-url = "' + $windows_startup_script_url + '"
#sysprep-specialize-script-url = "' + $windows_startup_script_url + '"

function provider_vpc($provider, $id, $platform_name, $vpc_cidr, $tags, $bool_igw) {
  $platform_name = $platform_name.tolower();
  switch($provider) {
    "aws" { add-tf_vpc_aws -id $id -platform_name $platform_name -vpc_cidr $vpc_cidr -tags $tags -bool_igw $bool_igw; }
    "gcp" { gcp_vpc -id $id -name "$platform_name-vpc" -boolautosubnets 'false' }
  }
}

function add-tf_vpc_aws($id, $platform_name, $vpc_cidr, $tags, $bool_igw) {
    $tf_output = aws_vpc -id $id -name "$platform_name-vpc" -cidr_block $vpc_cidr -tags $tags;
    if ($bool_igw -eq $true) {
        $tf_output += aws_internet_gateway -name "$platform_name-igw" -vpc_id $id -tags $tags;
    }
    return $tf_output
}

function Add-TFRouteTable($id, $platform_name, $vpc_id, $subnet_associations, $tags) {
    $tf_output = aws_route_table -id $id -name "$platform_name-$id" -vpc_id $vpc_id -tags 'var.tags'
    foreach ($subnet_id in $subnet_associations) {
        $tf_output += aws_route_table_association -id ("rta_"+$id+"_"+$subnet_id) -subnet_id $subnet_id -route_table_id $id;
    }
    return $tf_output;
}

function Add-TFPeering($platform_name, $vpc_id, $peering_connections, $region, $tags) {
  $peer_count = 0;
  $tf_output = $null;
  foreach ($peer in $peering_connections) {
      $peer_count++;
      $peer_name = $peer.name;
      $tf_output += aws_vpc_peering_connection -id "peer$peer_count" -name "$platform_name <-> $peer_name" -region $region -vpc_id $vpc_id -peer_vpc_id $peer.vpc_id -peer_owner_id $null -tags $tags
  }
  return $tf_output;
}

function aws_vpc($id, $name, $cidr_block, $tags) {
  if (!$id) { $id = 'vpc' };
 return '

resource "aws_vpc" "' + $id + '" {
  cidr_block    = "' + $cidr_block + '"
  tags = merge(
    map(
      "Name", "' + $name + '"
    ), ' + $tags + '
  )
}'
}
function gcp_vpc($id, $name, $boolautosubnets) {
 return '
 
resource "google_compute_network" "' + $id + '" {
  name = "' + $name + '"
  auto_create_subnetworks = ' + $boolautosubnets + '
}'
}

function aws_flow_log($log_destination, $vpc_id) {
 return '

resource "aws_flow_log" "vpc-flow-logs" {
  log_destination      = "' + $log_destination + '"
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.' + $vpc_id + '.id
}'
}

function gcp_flow_log() {
  return '
  
resource "google_storage_bucket" "log-bucket" {
  name = "my-unique-logging-bucket"
}'
}
function aws_customer_gateway ($id, $name, $bgp_asn, $ip_address, $type, $tags) {
 return '
 
 resource "aws_customer_gateway" "' + $id + '" {
  bgp_asn    = ' + $bgp_asn + '
  ip_address = "' + $ip_address + '"
  type       = "' + $type + '"

  tags = merge(
   map(
     "Name", "' + $name + '"
   ), ' + $tags + '
  )
}'
}
function provider_vpn_gateway ($provider, $id, $name, $vpc_id, $tags) {
  switch($provider) {
    "aws" { aws_vpn_gateway -id $id -name $name -vpc_id $vpc_id -tags $tags }
    "gcp" { gcp_vpn_gateway -id $id -name $name -vpc_id $vpc_id }
  }
}
function aws_vpn_gateway ($id, $name, $vpc_id, $tags) {
 return '
 
resource "aws_vpn_gateway" "' + $id + '" {
  vpc_id 				= aws_vpc.' + $vpc_id + '.id
  tags = merge(
   map(
     "Name", "' + $name + '"
   ), ' + $tags + '
 )
}'
}
function gcp_vpn_gateway ($id, $name, $vpc_id) {
  $name = $name.tolower();
  $name = $name.replace(' ','-');
 return '
 
resource "google_compute_vpn_gateway" "' + $id + '" {
  name    = "' + $name + '"
  network = google_compute_network.' + $vpc_id + '.self_link
}'
}
function aws_vpn_connection($id, $name, $vpn_gateway_id, $customer_gateway_id, $tags) {
 return '
 
resource "aws_vpn_connection" "' + $id + '" {
  vpn_gateway_id      = aws_vpn_gateway.' + $vpn_gateway_id + '.id
  customer_gateway_id = aws_customer_gateway.' + $customer_gateway_id + '.id
  type                = "ipsec.1"
  static_routes_only  = true
  tags = merge(
   map(
     "Name", "' + $name + '"
   ), ' + $tags + '
 )
}'
}
function aws_vpn_connection_route ($id, $destination_cidr_block, $vpn_connection_id) {
 return '
 
resource "aws_vpn_connection_route" "' + $id + '" {
  destination_cidr_block = "' + $destination_cidr_block + '"
  vpn_connection_id      = aws_vpn_connection.' + $vpn_connection_id + '.id
}'
}

function provider_subnet ($provider, $id, $name, $vpc_id, $cidr_block, $region, $az_letter, $tags, $bool_public_ip) {
  switch($provider) {
    "aws" { aws_subnet -id $id -name $name -vpc_id $vpc_id -cidr_block $cidr_block -region $region -az_letter $az_letter -tags $tags -map_public_ip_on_launch $bool_public_ip}
    "gcp" { gcp_subnet -id $id -name $name -vpc_id $vpc_id -cidr_block $cidr_block -region $region }
  }
}

function aws_subnet ($id, $name, $vpc_id, $cidr_block, $region, $az_letter, $tags, $map_public_ip_on_launch) {
 $tf_output = '

resource "aws_subnet" "' + $id + '" {
  vpc_id 						= aws_vpc.' + $vpc_id + '.id
  cidr_block 				= "' + $cidr_block + '"
  availability_zone = "' + ($region + $az_letter) + '"'
  if ($bool_public_ip -eq $true) {
    $tf_output+='
    map_public_ip_on_launch = true'
  }
  $tf_output+='
  tags = merge(
    map(
      "Name", "' + $name + '"
    ), ' + $tags + '
  )
}'
  return $tf_output;
}
function gcp_subnet ($id, $name, $vpc_id, $cidr_block, $region) {
  $name = $name.tolower();
  $name = $name.replace(' ','-');
  return '
  
resource "google_compute_subnetwork" "' + $id + '" {
  name          = "' + $name + '"
  ip_cidr_range = "' + $cidr_block + '"
  region        = "' + $region + '"
  network       = google_compute_network.' + $vpc_id + '.self_link

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}'
}
function aws_internet_gateway($name, $vpc_id, $tags) {
 return '
 
resource "aws_internet_gateway" "igw" {
  vpc_id 					= aws_vpc.' + $vpc_id + '.id
  tags = merge(
    map(
      "Name", "' + $name + '"
    ), ' + $tags + '
  )
}'
}
function provider_eip($id, $name, $tags) {
  switch($provider) {
    "aws" { aws_eip -id $id -name $name -tags $tags }
    "gcp" { gcp_eip -id $id -name $name }
  }
}
function aws_eip($id, $name, $tags, $instance_id) {
 $tf_output = '
 
resource "aws_eip" "' + $id + '" {
  vpc      		= true
  #depends_on 	= [aws_internet_gateway.igw]
  '
  if ($instance_id -ne $null) {
    $tf_output += 'instance = aws_instance.' + $instance_id + '.id
    '
  }
  
  $tf_output += 'tags = merge(
    map(
      "Name", "' + $name + '"
    ), ' + $tags + '
  )
}'
  return $tf_output;
}

function gcp_eip($id, $name) {
  $name = $name.tolower();
  $name = $name.replace(' ','-');
  return '
  
resource "google_compute_global_address" "' + $id + '" {
  name = "' + $name + '"
}'
}
function aws_nat_gateway ($id, $name, $elastic_ip_id, $subnet_id, $tags) {
 return '
 
resource "aws_nat_gateway" "' + $id + '" {
  allocation_id = aws_eip.' + $elastic_ip_id + '.id
  subnet_id 		= aws_subnet.' + $subnet_id + '.id
  depends_on 		= [aws_internet_gateway.igw]
  tags = merge(
    map(
      "Name", "' + $name + '"
    ), ' + $tags + '
  )
}'
}

function aws_route_table($id, $name, $vpc_id, $tags) {
 return '
 
resource "aws_route_table" "' + $id + '" {
  vpc_id = aws_vpc.' + $vpc_id + '.id
  tags = merge(
    map(
      "Name", "' + $name + '"
    ), ' + $tags + '
  )
}'
}
function aws_route_table_association($id, $subnet_id, $route_table_id) {
 return '
 
resource "aws_route_table_association" "' + $id + '" {
  subnet_id = aws_subnet.' + $subnet_id + '.id
  route_table_id = aws_route_table.' + $route_table_id + '.id
}'
}
function aws_network_acl($name, $vpc_id, $subnet_ids, $ingress, $egress, $tags) {
   $subnet_ids = $subnet_ids | % { 'aws_subnet.' + $_ + '.id'}
   $subnet_ids = $subnet_ids -join ',';

 return '
 
resource "aws_network_acl" "nacl" {
   vpc_id = aws_vpc.' + $vpc_id + '.id
   subnet_ids = [ ' + $subnet_ids + ']
    egress { 
      ' + $egress + ' 
    }
    ingress { 
      ' + $ingress + ' 
    }
  tags = merge(
      map(
        "Name", "' + $name + '"
      ), ' + $tags + '
    )
}'
}

function gcp_vpc_peering_connection ($id, $name, $vpc_id, $peer_vpc_id, $project_name) {
  return '

resource "google_compute_network_peering" "' + $id + '" {
  name         = "' + $name + '"
  network      = google_compute_network.' + $vpc_id + '.self_link
  peer_network = "projects/' + $project_name + '/global/networks/' + $peer_vpc_id + '"
}'
 
}

function aws_vpc_peering_connection ($id, $name, $region, $vpc_id, $peer_vpc_id, $peer_owner_id, $tags) {
 $TF = '

resource "aws_vpc_peering_connection" "' + $id + '" {
  ';
 if ($peer_owner_id -ne $null) {
    $TF+= 'peer_owner_id = "' + $peer_owner_id + '"';
 }
 $TF+='peer_vpc_id   = "' + $peer_vpc_id + '"
  vpc_id        = aws_vpc.' + $vpc_id + '.id
  peer_region   = "' + $region + '"
  tags = merge(
      map(
          "Name", "' + $name + '"
      ), ' + $tags + '
  )
}'
  return $TF;
}
function aws_vpc_endpoint($vpc_id, $name, $service_name, $route_table_ids, $policy, $tags) {
  $route_table_ids = $route_table_ids | % { 'aws_route_table.' + $_ + '.id'}
  $route_table_ids = $route_table_ids -join ',';

  return '
 
resource "aws_vpc_endpoint" "vpce_s3" {
    vpc_id = aws_vpc.' + $vpc_id + '.id
    service_name = "' + $service_name + '"
    route_table_ids = [ ' + $route_table_ids + ']
    tags = merge(
      map(
          "Name", "' + $name + '"
      ), ' + $tags + '
    )
    policy = <<POLICY
' + $policy + '
POLICY
}'
}