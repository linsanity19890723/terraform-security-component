data "aws_caller_identity" "current" {}


resource "random_id" "s3_id" {
  byte_length = 2
}

#Create cloudtrail 
resource "aws_cloudtrail" "foobar" {
  name                          = var.aws_cloudtrail_s3
  s3_bucket_name                = aws_s3_bucket.cloudtrail_s3.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

#Create cloudtrail s3 bucket
resource "aws_s3_bucket" "cloudtrail_s3" {
  bucket        = var.aws_cloudtrail_s3
  force_destroy = true

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${var.aws_cloudtrail_s3}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${var.aws_cloudtrail_s3}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}

#Create AWS config
resource "aws_config_delivery_channel" "foo" {
  name           = "example"
  s3_bucket_name = aws_s3_bucket.b.bucket
  depends_on     = [aws_config_configuration_recorder.foo]
}

#Create config s3 bucket
resource "aws_s3_bucket" "b" {
  bucket        = var.aws_config_s3
  force_destroy = true
}

resource "aws_config_configuration_recorder" "foo" {
  name     = "example"
  role_arn = aws_iam_role.r.arn
}

resource "aws_iam_role" "r" {
  name = "awsconfig-example"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "p" {
  name = "awsconfig-example"
  role = aws_iam_role.r.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.b.arn}",
        "${aws_s3_bucket.b.arn}/*"
      ]
    }
  ]
}
POLICY
}