##################################################################################
# VARIABLES
##################################################################################

variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "private_key_path" {}
variable "key_name" {}

##################################################################################
# PROVIDERS
##################################################################################

provider "aws" {
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
  region     = "eu-central-1"
}

variable "network_address_space" {
  default = "10.1.0.0/16"
}

variable "subnet1_address_space" {
  default = "10.1.0.0/24"
}
##################################################################################
# DATA
##################################################################################
#Image properties found with aws ec2 describe-images --owners amazon --filters 'Name=platform,Values=windows' 'Name=root-device-type,Values=ebs' 'Name=architecture,Values=x86_64' 'Name=state,Values=available' 'Name=name,Values=*2019*English*Base*'

data "aws_ami" "aws-windows-server" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["*2019-English-Full-Base-*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zones" "available" {}

##################################################################################
# RESOURCES
##################################################################################

resource "aws_vpc" "vpc" {
  cidr_block           = var.network_address_space
  enable_dns_hostnames = "true"

}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

}

resource "aws_subnet" "subnet1" {
  cidr_block              = var.subnet1_address_space
  vpc_id                  = aws_vpc.vpc.id
  map_public_ip_on_launch = "true"
  availability_zone       = data.aws_availability_zones.available.names[0]

}
# ROUTING #
resource "aws_route_table" "rtb" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "rta-subnet1" {
  subnet_id      = aws_subnet.subnet1.id
  route_table_id = aws_route_table.rtb.id
}

# Security Groups #
resource "aws_security_group" "allow_RDP" {
  name        = "windows_domain_network"
  description = "Allow port for RDP"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 1
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.subnet1_address_space]
  }
  ingress {
    from_port   = 1
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = [var.subnet1_address_space]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "domain-controller" {
  ami                    = data.aws_ami.aws-windows-server.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.subnet1.id
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.allow_RDP.id]
  get_password_data      = "true"
  user_data              = <<EOF
<powershell>
winrm quickconfig -q
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="300"}'
winrm set winrm/config '@{MaxTimeoutms="1800000"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
netsh advfirewall firewall add rule name="WinRM 5985" protocol=TCP dir=in localport=5985 action=allow
netsh advfirewall firewall add rule name="WinRM 5986" protocol=TCP dir=in localport=5986 action=allow
net stop winrm
sc.exe config winrm start=auto
net start winrm
</powershell>
EOF
  
  provisioner "remote-exec" {
    inline = [
      "powershell.exe Invoke-Expression ((New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1'))",
    ]

    connection {
      host     = coalesce(self.public_ip, self.private_ip)
      type     = "winrm"
      user     = "Administrator"
      password = "${rsadecrypt(aws_instance.domain-controller.password_data, file("aws.pem"))}"
      timeout  = "5m"
      https    = false
      port     = "5985"
    }
  }
  provisioner "local-exec" {
    working_dir = "ansible"
    command = "sleep 30; cp hosts.default hosts; sed -i 's/PUBLICIP/${aws_instance.domain-controller.public_ip}/g' hosts; sed -i 's/myTempPassword123/${replace(rsadecrypt(aws_instance.domain-controller.password_data, file("aws.pem")),"&","\\&")}/g' hosts; cp vars/vars.yml vars/vars.yml.backup; sed -i 's/replace_domain_admin_password/${rsadecrypt(aws_instance.domain-controller.password_data, file("aws.pem"))}/g' vars/vars.yml; sed -i 's/replace_safe_mode_password/${rsadecrypt(aws_instance.domain-controller.password_data, file("aws.pem"))}/g' vars/vars.yml; sed -i 's/replace_domain_controller_ip/${aws_instance.domain-controller.private_ip}/g' vars/vars.yml; ansible-playbook -i hosts playbooks/windows_dc.yml; mv vars/vars.yml.backup vars/vars.yml"
  }
    provisioner "remote-exec" {
    inline = [
      "powershell.exe \"Install-AdcsCertificationAuthority -AllowAdministratorInteraction -CACommonName 'pkitest Root CA 1' -CADistinguishedNameSuffix 'DC=pkitest,DC=local' -CAType EnterpriseRootCa -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 4096 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 15 -Confirm -Force\"",
    ]

    connection {
      host     = coalesce(self.public_ip, self.private_ip)
      type     = "winrm"
      user     = "Administrator"
      password = "${rsadecrypt(aws_instance.domain-controller.password_data, file("aws.pem"))}"
      timeout  = "5m"
      https    = false
      port     = "5985"
    }
  }
}

##################################################################################
# OUTPUT
##################################################################################

output "domain-controller_public_dns" {
  value  = aws_instance.domain-controller.public_dns
}

output "domain-controller_ec2_password" { 
  value = "${rsadecrypt(aws_instance.domain-controller.password_data, file("aws.pem"))}" 
  
}
