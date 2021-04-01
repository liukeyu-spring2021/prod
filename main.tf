
provider "aws" {
    profile = "prod"
    region = var.region
}

resource "aws_vpc" "vpc-1" {
    cidr_block              = "10.0.0.0/16"
    enable_dns_hostnames    = true
    enable_dns_support      = true
    assign_generated_ipv6_cidr_block = false
}
resource "aws_vpc" "vpc-2" {
    cidr_block              = "10.2.0.0/16"
    enable_dns_hostnames    = true
    enable_dns_support      = true
    assign_generated_ipv6_cidr_block = false
}
resource "aws_vpc" "vpc-3" {
    cidr_block              = "10.3.0.0/16"
    enable_dns_hostnames    = true
    enable_dns_support      = true
    assign_generated_ipv6_cidr_block = false
}



resource "aws_subnet" "subnet-1" {
    cidr_block              = "10.0.1.0/24"
    vpc_id                  = aws_vpc.vpc-1.id
    availability_zone       = var.az1
    map_public_ip_on_launch = true
    tags = {
        Name = "csye6225-subnet-1"
    }
}

resource "aws_subnet" "subnet-2" {
    cidr_block              = "10.0.2.0/24"
    vpc_id                  = aws_vpc.vpc-1.id
    availability_zone       = var.az2
    map_public_ip_on_launch = true
    tags = {
        Name = "csye6225-subnet-2"
    }
}

resource "aws_subnet" "subnet-3" {
    cidr_block              = "10.0.3.0/24"
    vpc_id                  = aws_vpc.vpc-1.id
    availability_zone       = var.az3
    map_public_ip_on_launch = true
    tags = {
        Name = "csye6225-subnet-3"
    }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.vpc-1.id
}

resource "aws_route" "r" {
    route_table_id = aws_vpc.vpc-1.default_route_table_id
    destination_cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
resource "aws_route_table" "routetable" {
    vpc_id = aws_vpc.vpc-1.id
    route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.gw.id
    }
    tags = {
      Name = "Main"
    }
  }
  resource "aws_route_table_association" "a" {
    subnet_id = aws_subnet.subnet-1.id
    route_table_id = aws_route_table.routetable.id
  }
  resource "aws_route_table_association" "b" {
    subnet_id = aws_subnet.subnet-2.id
    route_table_id = aws_route_table.routetable.id
  }
  resource "aws_route_table_association" "c" {
    subnet_id = aws_subnet.subnet-3.id
    route_table_id = aws_route_table.routetable.id
  }

resource "aws_security_group" "ec2" {
  name        = "ec2"
  vpc_id      = aws_vpc.vpc-1.id
  description = "EC2 Security group"
  

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }

}

resource "aws_security_group" "DB" {
  name        = "DB"
  description = "RDS Security group"
  vpc_id      = aws_vpc.vpc-1.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "bucket" {
  bucket = "webapps32"
  force_destroy  = true
  acl = "private"
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
      }
    }
  }
    lifecycle_rule {
    prefix  = "config/"
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}
data "aws_iam_policy_document" "WebAppS3" {
  version = "2012-10-17"
  statement {
    actions = ["s3:PutObject",
      "s3:PutObjectAcl",
      "s3:CreateBucket",
      "s3:DeleteBucket",
      "s3:DeleteObject"
    ]
    effect = "Allow"
    resources = ["arn:aws:s3:::webapps32",
                 "arn:aws:s3:::webapps32/*"]
  }
}

data "aws_iam_policy_document" "instance-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_db_subnet_group" "dbsubnet" {
  name = "dbsubnet"
  subnet_ids = [aws_subnet.subnet-1.id,aws_subnet.subnet-2.id]
}
resource "aws_db_instance" "webappdb" {

  engine               = "mysql"
  engine_version       = "8.0.21"
  instance_class       = "db.t3.micro"
  name                 = var.dbname
  username             = var.dbusername
  password             = var.dbpassword
  multi_az             = "false"
  identifier           =  "csye6225-f20"
  db_subnet_group_name =  aws_db_subnet_group.dbsubnet.name
  publicly_accessible    =  "false"
  vpc_security_group_ids = [aws_security_group.DB.id]
  skip_final_snapshot = true
  final_snapshot_identifier = "webappdbsnapshot"
  allocated_storage = 20
}
/* WebAppSecurityGroup is for auto-scaling, while application is for ec2
we are using auto-scaling instead of ec2, so comment here
resource "aws_instance" "webapp" {

  ami           = var.amiID
  instance_type = "t2.micro"
  subnet_id = aws_subnet.subnet-1.id
  vpc_security_group_ids = [aws_security_group.ec2.id]
  user_data = <<EOF
    #!/bin/bash
    echo user="root" >> /etc/environment
    echo password="liukeyu521" >> /etc/environment
    echo host="csye6225-f20.cbcz4zpbrrbg.us-east-1.rds.amazonaws.com" >> /etc/environment
    echo bucketname="webapps32" >> /etc/environment
  EOF


  root_block_device {
    volume_size = 20
    volume_type = "gp2"
    delete_on_termination = true
  }

  key_name = "CSYE"
  associate_public_ip_address = true
  depends_on = [aws_db_instance.webappdb]
  iam_instance_profile = aws_iam_instance_profile.profile1.name

  tags = {
    Name = "CodeDeployInstance"
  }

}
*/

resource "aws_iam_policy" "WebAppS3" {
  name = "WebAppS3"
  policy = data.aws_iam_policy_document.WebAppS3.json
}
resource "aws_iam_role" "EC2-CSYE6225" {
  name = "EC2-CSYE6225"
  assume_role_policy = data.aws_iam_policy_document.instance-assume-role-policy.json
}
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"
  assume_role_policy = data.aws_iam_policy_document.instance-assume-role-policy.json
}

resource "aws_iam_policy_attachment" "attach" {
  name = "attach-test"
  policy_arn = aws_iam_policy.WebAppS3.arn
  roles = [aws_iam_role.EC2-CSYE6225.name]
}
resource "aws_iam_policy_attachment" "attach1" {
  name = "attach-test1"
  policy_arn = aws_iam_policy.CodeDeploy-EC2-S3.arn
  roles = [aws_iam_role.CodeDeployEC2ServiceRole.name]
}
resource "aws_iam_policy_attachment" "attach_cloud_watch_policy_to_ec2_role" {
  name       = var.attach_cloud_watch_policy_to_ec2_role_name
  roles      = [aws_iam_role.CodeDeployEC2ServiceRole.name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}


resource "aws_iam_instance_profile" "profile" {
  name = "test-profile"
  role = aws_iam_role.EC2-CSYE6225.name
}
resource "aws_iam_instance_profile" "profile1" {
  name = "CodeDeployEC2ServiceRole"
  role = aws_iam_role.CodeDeployEC2ServiceRole.name
}


resource "aws_iam_user_policy" "GH-Upload-To-S3" {
  name = "GH-Upload-To-S3"
  user = var.aws_user
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.6225csyekeyuliu.me.prod",
                "arn:aws:s3:::codedeploy.6225csyekeyuliu.me.prod/*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  path        = "/"
  description = "CodeDeploy-EC2-S3"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*",
                "s3:DeleteBucket",
                "s3:DeleteObject"
            ],
            "Resource": [            
                 "*"
            ]
        }
    ]
}
EOF
} 

resource "aws_iam_user_policy" "CloudWatchAgentAdmin" {
  name = "CloudWatchAgentAdmin"
  user = var.aws_user
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:PutParameter"
            ],
            "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
        }
    ]
}
EOF
}

resource "aws_iam_user_policy" "CloudWatchAgentService" {
  name = "CloudWatchAgentService"
  user = var.aws_user
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "ec2:DescribeVolumes",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
        }
    ]
}
EOF
}

resource "aws_iam_user_policy" "GH-Code-Deploy" {
  name = "GH-Code-Deploy"
  user = var.aws_user
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        { 
            "Effect": "Allow",
            "Action": [
                "codedeploy:RegisterApplicationRevision",
                "codedeploy:GetApplicationRevision"
            ],
            "Resource": [
                  "arn:aws:codedeploy:us-east-1:359410113455:application:csye6225-webapp"
            ]
        },
        { 
            "Effect": "Allow",
            "Action": [
                "codedeploy:CreateDeployment",
                "codedeploy:GetDeployment"
            ],
            "Resource": [
                "*"
            ]
        },
        { 
            "Effect": "Allow",
            "Action": [
                "codedeploy:GetDeploymentConfig"
            ],
            "Resource": [
                "arn:aws:codedeploy:us-east-1:359410113455:deploymentconfig:CodeDeployDefault.OneAtATime",
                "arn:aws:codedeploy:us-east-1:359410113455:deploymentconfig:CodeDeployDefault.HalfAtATime",
                "arn:aws:codedeploy:us-east-1:359410113455:deploymentconfig:CodeDeployDefault.AllAtOnce"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "AWSCodeDeployRole" {
  name = "AWSCodeDeployRole"
  role = aws_iam_role.CodeDeployServiceRole.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "autoscaling:CompleteLifecycleAction",
                "autoscaling:DeleteLifecycleHook",
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeLifecycleHooks",
                "autoscaling:PutLifecycleHook",
                "autoscaling:RecordLifecycleActionHeartbeat",
                "autoscaling:CreateAutoScalingGroup",
                "autoscaling:UpdateAutoScalingGroup",
                "autoscaling:EnableMetricsCollection",
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribePolicies",
                "autoscaling:DescribeScheduledActions",
                "autoscaling:DescribeNotificationConfigurations",
                "autoscaling:DescribeLifecycleHooks",
                "autoscaling:SuspendProcesses",
                "autoscaling:ResumeProcesses",
                "autoscaling:AttachLoadBalancers",
                "autoscaling:AttachLoadBalancerTargetGroups",
                "autoscaling:PutScalingPolicy",
                "autoscaling:PutScheduledUpdateGroupAction",
                "autoscaling:PutNotificationConfiguration",
                "autoscaling:PutLifecycleHook",
                "autoscaling:DescribeScalingActivities",
                "autoscaling:DeleteAutoScalingGroup",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus",
                "ec2:TerminateInstances",
                "tag:GetResources",
                "sns:Publish",
                "cloudwatch:DescribeAlarms",
                "cloudwatch:PutMetricAlarm",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeInstanceHealth",
                "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
                "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:RegisterTargets",
                "elasticloadbalancing:DeregisterTargets"
            ],
            "Resource": "*"
        }
    ]
  }
  EOF
}

resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOF
}




# -------------------------------------------------------------------
# load balancer aws_security_group
resource "aws_security_group" "load_balancer" {
  name        = "security-group-lb"
  description = "only allow 80 for ingress"
  vpc_id      = aws_vpc.vpc-1.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.security_group_cidr_block]
  }
}

resource "aws_security_group_rule" "lb_sgr" {
  count             = length(var.aws_security_group_lb_ingress_port)
  type              = var.security_group_rule_in
  from_port         = element(var.aws_security_group_lb_ingress_port,count.index)
  to_port           = element(var.aws_security_group_lb_ingress_port,count.index)
  protocol          = var.security_group_protocl_in
  cidr_blocks       = [var.security_group_cidr_block]
  security_group_id = aws_security_group.load_balancer.id
}

# -------------------------------------------------------------------
# Autoscaling Launch Configuration Security Group: WebAppSecurityGroup
resource "aws_security_group" "autoscale_launch_config" {
  name        = var.aws_autoscale_launch_config_security_group
  description = var.aws_security_group_app_desc
  vpc_id      = aws_vpc.vpc-1.id

  egress {
    from_port   = var.all_port
    to_port     = var.all_port
    protocol    = var.security_group_protocl_e
    cidr_blocks = [var.security_group_cidr_block]
  }

  tags = {
    Name = var.aws_autoscale_launch_config_security_group
  }
}

resource "aws_security_group_rule" "autoscale_launch_config_sgr" {
  count             = length(var.aws_security_group_ingress_port)
  type              = var.security_group_rule_in
  from_port         = element(var.aws_security_group_ingress_port,count.index)
  to_port           = element(var.aws_security_group_ingress_port,count.index)
  protocol          = var.security_group_protocl_in
  #cidr_blocks       = [var.security_group_cidr_block]
  security_group_id = aws_security_group.autoscale_launch_config.id
  #security_groups   = [aws_security_group.load_balancer.id]
  source_security_group_id  = aws_security_group.load_balancer.id
}

/*resource "aws_subnet" "subnet123" {
  count = length(var.subnet_cidr_block)
  cidr_block           = element(var.subnet_cidr_block,count.index)
  vpc_id = aws_vpc.vpc-1.id
  availability_zone    = element(var.azs,count.index)
  map_public_ip_on_launch = true
  tags = {
    Name = "subnet-${var.vers}-${count.index}"
  }
}*/

# -------------------------------------------------------------------
# Application Load Balancer
resource "aws_lb" "app_lb" {
  name               = var.app_load_balancer_name
  internal           = var.fbool
  load_balancer_type = var.app_load_balancer_type
  security_groups    = [aws_security_group.load_balancer.id]
  subnets            = [aws_subnet.subnet-1.id,aws_subnet.subnet-2.id]
}

# -------------------------------------------------------------------
# target group
resource "aws_lb_target_group" "lb_target_group" {
  name     = var.lb_target_group_name
  port     = var.lb_target_group_port
  protocol = var.app_load_balancer_protocol
  vpc_id   = aws_vpc.vpc-1.id
  health_check{
    path     = "/v1/users"
    port     = 8080
    interval = 300
  }
}

# Application Load Balancer listener: http-80
resource "aws_lb_listener" "app_lb_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = var.app_lb_listener_port
  protocol          = var.app_load_balancer_protocol
  default_action {
    type             = var.app_load_balancer_action_type
    target_group_arn = aws_lb_target_group.lb_target_group.arn
  }
}

# Application Load Balancer listener: https-443
/*resource "aws_lb_listener" "app_lb_listener_https" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = data.aws_acm_certificate.issued.arn

  default_action {
    type             = var.app_load_balancer_action_type
    target_group_arn = aws_lb_target_group.lb_target_group.arn
  }
}*/
# -------------------------------------------------------------------
# Autoscaling Launch Configuration for EC2 Instances
resource "aws_launch_configuration" "aws_conf" {
  name          = var.aws_launch_configuration_name
  image_id      = var.amiID
  instance_type = "t2.micro"
  key_name                    = "CSYE"
  associate_public_ip_address = var.tbool
  /*
  user_data                   = <<EOF
#!/bin/bash
echo DB_USERNAME="${var.rds_username}" >> /etc/environment
echo DB_PASSWORD="${var.password}" >> /etc/environment
echo DB_NAME="${var.aws_dynamodb_table_name}" >> /etc/environment
echo DBHOSTNAME="${aws_db_instance.db.endpoint}" >> /etc/environment
echo BUCKET_NAME="${var.aws_s3_bucket_name}" >> /etc/environment
  EOF
  */
  iam_instance_profile        = aws_iam_instance_profile.profile1.name
  security_groups             = [aws_security_group.autoscale_launch_config.id]

  root_block_device {
    volume_type            = "gp2"
    volume_size            = 20
    delete_on_termination  = true
  }
}

# -------------------------------------------------------------------
# Autoscaling group
resource "aws_autoscaling_group" "aws_autoscale_gr" {
  name                      = var.aws_autoscaling_group_name
  default_cooldown          = 60
  launch_configuration      = aws_launch_configuration.aws_conf.name
  health_check_grace_period = 300
  health_check_type         = "EC2"
  max_size                  = 5
  min_size                  = 3
  desired_capacity          = 3
  vpc_zone_identifier       = aws_subnet.subnet-1.*.id

  tag {
    key                     = var.aws_autoscaling_group_tag_key
    value                   = var.aws_autoscaling_group_tag_value
    propagate_at_launch     = var.tbool
  }

  target_group_arns         = [aws_lb_target_group.lb_target_group.arn]
}

# -------------------------------------------------------------------
# Autoscaling group scale up policy
resource "aws_autoscaling_policy" "autoscaling_scale_up_policy" {
  name                   = var.aws_autoscaling_scale_up_policy_name
  scaling_adjustment     = var.aws_autoscaling_scale_up_policy_scaling_adjustment
  adjustment_type        = var.aws_autoscaling_scale_up_policy_adjustment_type
  cooldown               = var.aws_autoscaling_scale_up_policy_cooldown
  autoscaling_group_name = aws_autoscaling_group.aws_autoscale_gr.name
}

# -------------------------------------------------------------------
# cloud watch alarm for Autoscaling group scale up policy
resource "aws_cloudwatch_metric_alarm" "cloudwatch_scale_up_alarm" {
  alarm_name          = var.cloudwatch_scale_up_alarm_name
  alarm_description   = var.cloudwatch_scale_up_alarm_description
  metric_name         = var.cloudwatch_scale_up_alarm_metric_name
  namespace           = var.cloudwatch_scale_up_alarm_namespace
  statistic           = var.cloudwatch_scale_up_alarm_statistic
  period              = var.cloudwatch_scale_up_alarm_period
  evaluation_periods  = "10"
  threshold           = var.cloudwatch_scale_up_alarm_threshold
  alarm_actions       = [aws_autoscaling_policy.autoscaling_scale_up_policy.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.aws_autoscale_gr.name
  }
  comparison_operator = var.cloudwatch_scale_up_alarm_comparison_operator
}

# -------------------------------------------------------------------
# Autoscaling group scale down policy
resource "aws_autoscaling_policy" "autoscaling_scale_down_policy" {
  name                   = var.aws_autoscaling_scale_down_policy_name
  scaling_adjustment     = var.aws_autoscaling_scale_down_policy_scaling_adjustment
  adjustment_type        = var.aws_autoscaling_scale_up_policy_adjustment_type
  cooldown               = var.aws_autoscaling_scale_up_policy_cooldown
  autoscaling_group_name = aws_autoscaling_group.aws_autoscale_gr.name
}

# -------------------------------------------------------------------
# cloud watch alarm for Autoscaling group scale down policy
resource "aws_cloudwatch_metric_alarm" "cloudwatch_scale_down_alarm" {
  alarm_name          = var.cloudwatch_scale_down_alarm_name
  alarm_description   = var.cloudwatch_scale_down_alarm_description
  metric_name         = var.cloudwatch_scale_up_alarm_metric_name
  namespace           = var.cloudwatch_scale_up_alarm_namespace
  statistic           = var.cloudwatch_scale_up_alarm_statistic
  period              = var.cloudwatch_scale_up_alarm_period
  evaluation_periods  = "10"
  threshold           = var.cloudwatch_scale_down_alarm_threshold
  alarm_actions       = [aws_autoscaling_policy.autoscaling_scale_down_policy.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.aws_autoscale_gr.name
  }
  comparison_operator = var.cloudwatch_scale_down_alarm_comparison_operator
}

# -------------------------------------------------------------------
# DNS record of ec2 public ip
data "aws_route53_zone" "webapp_route53_hosted_zone"{
  name          = var.domain_name
  private_zone = false
}

resource "aws_route53_record" "lb_alias_record" {
  zone_id = data.aws_route53_zone.webapp_route53_hosted_zone.zone_id
  name    = format("%s.6225csyekeyuliu.me.", var.env)
  type    = "A"

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = var.fbool
  }
}

/*
resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.webapp_route53_hosted_zone.zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = "60"
  records = [aws_instance.webapp.public_ip]
}
*/

/*
# -------------------------------------------------------------------
# ssh key pair
resource "aws_key_pair" "ssh" {
  key_name   = var.aws_key_pair_name
  public_key = var.aws_key_pair_key
}
*/

/*# -------------------------------------------------------------------
# Create CodeDeploy Application
resource "aws_codedeploy_app" "codedeploy_app" {
  compute_platform = var.codedeploy_app_cp
  name             = var.codedeploy_app_name
}
# -------------------------------------------------------------------
# Create CodeDeploy Deployment Group
resource "aws_codedeploy_deployment_group" "codedeploy_deployment_group" {
  app_name              = aws_codedeploy_app.codedeploy_app.name
  deployment_group_name = var.codedeploy_deployment_group_name
  service_role_arn      = aws_iam_role.code_deploy_service_role.arn
  deployment_config_name = var.codedeploy_deployment_group_deployment_config_name

  deployment_style {
    deployment_type = var.codedeploy_deployment_group_deployment_style
  }

  ec2_tag_set {
    ec2_tag_filter {
      key   = var.codedeploy_deployment_group_ec2_tag_filter_key
      type  = var.codedeploy_deployment_group_ec2_tag_filter_type
      value = var.codedeploy_deployment_group_ec2_tag_filter_value
    }
  }

  auto_rollback_configuration {
    enabled = var.fbool
    # events  = ["DEPLOYMENT_FAILURE"]
  }
}*/