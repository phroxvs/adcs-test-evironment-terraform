# adcs-test-evironment-terraform
Terraform and Ansible script to setup a Active Directory Certificate Services test environment in AWS. Ansible script is largely based on https://github.com/d1vious/building-a-windows-dc-terraform.

## Usage
1. Install terraform (see https://learn.hashicorp.com/tutorials/terraform/install-cli) and ansible 
2. Insert your AWS access key and AWS SSH key particulars into terraform.tfvars
3. Check that ansible/ansible.cfg is not world-writable
4. Execute ```terraform init``` and then ```terraform apply```
5. Connect with RDP to the Domain Controller and have fun :-)