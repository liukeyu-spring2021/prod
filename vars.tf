variable "region" {
  default = "us-east-1"
}
variable "az1" {
  default = "us-east-1a"
}
variable "az2" {
  default = "us-east-1b"
}
variable "az3" {
  default = "us-east-1c"
}
variable "dbusername" {
  default = "root"
}
variable "dbpassword" {
  default = "liukeyu521"
}
variable "dbname" {
  default = "db_cloud"
}
variable "amiID"{
    default = "ami-0cc47deb29ad01449"
}
variable "aws_user" {
  default = "ghaction"
}

variable "domain_name" {
  type = string
  default = "prod.6225csyekeyuliu.me"
}

variable "tbool" {
  type = bool
  default = true
}

variable "fbool" {
  type = bool
  default = false
}

variable "hostedzone" {
  type = string
  default = "prod.6225csyekeyuliu.me"
}

variable "env" {
  type = string
  default = "prod"
}

variable "dns_a_record_type" {
  type = string
  default = "A"
}

variable "dns_a_record_ttl" {
  type = string
  default = "60"
}

# -------------------------------------------------------------------
# load balancer
variable "app_load_balancer_name" {
  type = string
  default = "app-load-balancer"
}

variable "app_load_balancer_type" {
  type = string
  default = "application"
}

# -------------------------------------------------------------------
# target group
variable "lb_target_group_name" {
  type = string
  default = "lb-target-group"
}

variable "lb_target_group_port" {
  type = number
  default = "8080"
}

# Application Load Balancer listener
variable "app_lb_listener_port" {
  type = number
  default = "80"
}

variable "app_load_balancer_protocol" {
  type = string
  default = "HTTP"
}

variable "app_load_balancer_action_type" {
  type = string
  default = "forward"
}

variable "app_load_balancer_action_redirect_path" {
  type = string
  default = "/"
}

variable "app_load_balancer_action_redirect_port" {
  type = number
  default = "8080"
}

variable "app_load_balancer_action_redirect_code" {
  type = string
  default = "HTTP_301"
}

# -------------------------------------------------------------------
# ssh key pair
variable "aws_key_pair_name" {
  type = string
  default = "ubuntu"
}

variable "aws_key_pair_key" {
  type = string
  default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDoHTdtSqCFc+YCRHJvAFCVru2PmjePatrsuczKYGDP4E/9tNqOUTIZwiG7GYwFJ5Wchh9Ev9VNx6Nf+pfOVEHXSrSPm+9y2NXZYXdycxKrbB5MPb1MWYtb/WyOuwYCFukPVS/T9ctEa6De1NeHJ9xyiwo0yCGIh5YSneUBObxjNXFNE1j0d8lC2qJKyTvXubsI7E4sZp2GmvwNqKtGb1OgX7Eu/RFTdmbScpJ5xAQXYmvWWsK0dR5+40dX4wYtaD4K8ut1cRr6cixborLLhpCibYIKacrTIMIuiykREXj2inVcO7Ut/ZnGTl2uU/YdOgdqzH8zqknV6it7L6Iz5TLn martin@66.local"
}