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
    default = "ami-05bc185d25a35f6bc"
}

variable "aws_user" {
  default = "ghaction"
}

variable "tbool" {
  type = bool
  default = true
}

variable "fbool" {
  type = bool
  default = false
}

variable "attach_cloud_watch_policy_to_ec2_role_name" {
  type = string
  default = "cloud_watch_policy_to_ec2_role_attach"
}

# -------------------------------------------------------------------
# VPC
variable "vers" {
  type = string
  default = "04"
}

variable "security_group_protocl_in" {
  type = string
  default = "tcp"
}

variable "security_group_protocl_e" {
  type = string
  default = "-1"
}

variable "security_group_rule_in" {
  type = string
  default = "ingress"
}

variable "all_port" {
  type = number
  default = 0
}

variable "db_port" {
  type = number
  default = 3306
}

variable "db_cidr_block" {
  type = string
  default = "10.0.0.0/16"
}

variable "aws_security_group_ingress_port" {
  type = list(number)
  default = [22, 80, 443, 8080]
}

variable "security_group_cidr_block" {
  type = string
  default = "0.0.0.0/0"
}

variable "destination" {
  type = string
  default = "0.0.0.0/0"
}

variable "cidr_block" {
  type = string
  default = "10.0.0.0/16"
}

variable "subnet_cidr_block" {
  type = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "azs" {
 type = list(string)
 default = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

# -------------------------------------------------------------------
# load balancer aws_security_group
variable "aws_security_group_lb_ingress_port" {
  type = list(number)
  default = [80, 443]
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
/*
# -------------------------------------------------------------------
# ssh key pair
variable "aws_key_pair_name" {
  type = string
  default = "CSYE"
}

variable "aws_key_pair_key" {
  type = string
  default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDoHTdtSqCFc+YCRHJvAFCVru2PmjePatrsuczKYGDP4E/9tNqOUTIZwiG7GYwFJ5Wchh9Ev9VNx6Nf+pfOVEHXSrSPm+9y2NXZYXdycxKrbB5MPb1MWYtb/WyOuwYCFukPVS/T9ctEa6De1NeHJ9xyiwo0yCGIh5YSneUBObxjNXFNE1j0d8lC2qJKyTvXubsI7E4sZp2GmvwNqKtGb1OgX7Eu/RFTdmbScpJ5xAQXYmvWWsK0dR5+40dX4wYtaD4K8ut1cRr6cixborLLhpCibYIKacrTIMIuiykREXj2inVcO7Ut/ZnGTl2uU/YdOgdqzH8zqknV6it7L6Iz5TLn martin@66.local"
}*/


# -------------------------------------------------------------------
# Autoscaling Launch Configuration for EC2 Instances
variable "aws_launch_configuration_name" {
  type = string
  default = "asg_launch_config"
}

# -------------------------------------------------------------------
# Autoscaling group
variable "aws_autoscaling_group_name" {
  type = string
  default = "aws_autoscaling_group"
}

variable "aws_autoscaling_group_tag_key" {
  type = string
  default = "Name"
}

variable "aws_autoscaling_group_tag_value" {
  type = string
  default = "CodeDeployInstance"
}

# -------------------------------------------------------------------
# Autoscaling group scale up policy
variable "aws_autoscaling_scale_up_policy_name" {
  type = string
  default = "WebServerScaleUpPolicy"
}

variable "aws_autoscaling_scale_up_policy_scaling_adjustment" {
  type = number
  default = 1
}

variable "aws_autoscaling_scale_up_policy_adjustment_type" {
  type = string
  default = "ChangeInCapacity"
}

variable "aws_autoscaling_scale_up_policy_cooldown" {
  type = number
  default = 60
}

# -------------------------------------------------------------------
# Autoscaling group scale down policy
variable "aws_autoscaling_scale_down_policy_name" {
  type = string
  default = "WebServerScaleDownPolicy"
}

variable "aws_autoscaling_scale_down_policy_scaling_adjustment" {
  type = number
  default = -1
}

# -------------------------------------------------------------------
# cloud watch alarm for Autoscaling group scale up policy
variable "cloudwatch_scale_up_alarm_name" {
  type = string
  default = "CPUAlarmHigh"
}

variable "cloudwatch_scale_up_alarm_description" {
  type = string
  default = "Scale-up if CPU > 5% for 10 minutes"
}

variable "cloudwatch_scale_up_alarm_metric_name" {
  type = string
  default = "CPUUtilization"
}

variable "cloudwatch_scale_up_alarm_namespace" {
  type = string
  default = "AWS/EC2"
}

variable "cloudwatch_scale_up_alarm_statistic" {
  type = string
  default = "Average"
}

variable "cloudwatch_scale_up_alarm_period" {
  type = number
  default = 60
}

variable "cloudwatch_scale_up_alarm_threshold" {
  type = number
  default = 5
}

variable "cloudwatch_scale_up_alarm_comparison_operator" {
  type = string
  default = "GreaterThanThreshold"
}

# -------------------------------------------------------------------
# cloud watch alarm for Autoscaling group scale down policy
variable "cloudwatch_scale_down_alarm_name" {
  type = string
  default = "CPUAlarmLow"
}

variable "cloudwatch_scale_down_alarm_description" {
  type = string
  default = "Scale-down if CPU < 3% for 10 minutes"
}

variable "cloudwatch_scale_down_alarm_period" {
  type = number
  default = 60
}

variable "cloudwatch_scale_down_alarm_evaluation_periods" {
  type = number
  default = 3
}

variable "cloudwatch_scale_down_alarm_threshold" {
  type = number
  default = 2
}

variable "cloudwatch_scale_down_alarm_comparison_operator" {
  type = string
  default = "LessThanThreshold"
}

# -------------------------------------------------------------------
# DNS record of ec2 public ip

variable "domain_name" {
  type = string
  default = "prod.6225csyekeyuliu.me"
}

variable "hostedzone" {
  type = string
  default = "6225csyekeyuliu.me"
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
# Create CodeDeploy Application
variable "codedeploy_app_name" {
  type = string
  default = "csye6225-webapp"
}

variable "codedeploy_app_cp" {
  type = string
  default = "Server"
}

# -------------------------------------------------------------------
# ec2 aws_security_group
variable "aws_security_group_app" {
  type = string
  default = "application"
}

variable "aws_security_group_app_desc" {
  type = string
  default = "security group for application"
}

# -------------------------------------------------------------------
# Autoscaling Launch Configuration Security Group: WebAppSecurityGroup
variable "aws_autoscale_launch_config_security_group" {
  type = string
  default = "WebAppSecurityGroup"
}

variable "aws_autoscale_launch_config_security_group_desc" {
  type = string
  default = "security group for Autoscaling Launch Configuration"
}

# -------------------------------------------------------------------
# Create CodeDeploy Deployment Group
variable "codedeploy_deployment_group_name" {
  type = string
  default = "csye6225-webapp-deployment"
}

variable "codedeploy_deployment_group_deployment_style" {
  type = string
  default = "IN_PLACE"
}

variable "codedeploy_deployment_group_deployment_config_name" {
  type = string
  default = "CodeDeployDefault.AllAtOnce"
}

variable "codedeploy_deployment_group_ec2_tag_filter_key" {
  type = string
  default = "Name"
}

variable "codedeploy_deployment_group_ec2_tag_filter_type" {
  type = string
  default = "KEY_AND_VALUE"
}

variable "codedeploy_deployment_group_ec2_tag_filter_value" {
  type = string
  default = "ubuntu"
}


