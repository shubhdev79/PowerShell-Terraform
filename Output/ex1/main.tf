
  
provider "aws" {
  region     = "us-east-1"
  version     = "~> 2.34.0"
}

resource "aws_vpc" "ex1-vpc1" {
  cidr_block    = "10.0.9.0/24"
  tags = merge(
    map(
      "Name", "ex1-vpc"
    ), 
  )
}
 
resource "aws_internet_gateway" "igw" {
  vpc_id 					= aws_vpc.ex1-vpc1.id
  tags = merge(
    map(
      "Name", "ex1-igw"
    ), 
  )
}

resource "aws_subnet" "ex1-public1" {
  vpc_id 						= aws_vpc.ex1-vpc1.id
  cidr_block 				= "10.0.9.0/27"
  availability_zone = "us-east-1a"
  tags = merge(
    map(
      "Name", "ex1 Public 1"
    ), 
  )
}
    
resource "aws_security_group" "ex1-sg1" {
  name              = "ex1-sg1"
  vpc_id            = aws_vpc.ex1-vpc1.id
      ingress {
        description = ""
        from_port   = 3389
        to_port     = 3389
        protocol    = "tcp"
        cidr_blocks = [ "47.55.127.100/32" ]
      }
      ingress {
        description = ""
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [ "10.0.9.0/24" ]
      }
      ingress {
        description = ""
        from_port   = 3389
        to_port     = 3389
        protocol    = "tcp"
        cidr_blocks = [ "172.16.0.0/16" ]
      }
      egress {
        description = ""
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [ "10.0.9.0/24" ]
      }
      egress {
        description = ""
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [ "10.0.0.0/16" ]
      }
      egress {
        description = ""
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = [ "0.0.0.0/0" ]
      }
  tags = merge(
    map(
      "Name", "ex1-sg1"
    ), 
  )
  
}
  
resource "aws_kms_key" "kms_ebs_key1" {
  description             = "EBS key for kms_ebs_key1"
  enable_key_rotation     = true
  tags = merge(
    map(
      "Name", "kms_ebs_key1",
    ), 
  )
}

resource "aws_kms_alias" "kms_ebs_key1_alias" {
  name                    = "alias/kms_ebs_key1_alias"
  target_key_id           = aws_kms_key.kms_ebs_key1.id
}

  
resource "aws_instance" "ex1-dc1" {
  ami                     = "ami-08bf5f54919fada4a"
  instance_type           = "t2.large"
  subnet_id               = aws_subnet.ex1-public1.id
  disable_api_termination = "false"
  ebs_optimized           = "false"
  private_ip              = "10.0.9.10"
  key_name                = "CISO"
  source_dest_check       = "false"
  vpc_security_group_ids  = [ aws_security_group.ex1-sg1.id ]
  #user_data               = ""
  lifecycle {
    ignore_changes = [user_data, user_data_base64]
  }
  
  tags = merge(
    map(
      "Name", "ex1-dc1"
    ), 
  )
  root_block_device {
    volume_type = "gp2"
    volume_size = "30"
    delete_on_termination = true
  }
}

 
resource "aws_eip" "ex1-dc1-eip" {
  vpc      		= true
  #depends_on 	= [aws_internet_gateway.igw]
  instance = aws_instance.ex1-dc1.id
    tags = merge(
    map(
      "Name", "ex1-dc1"
    ), 
  )
}
