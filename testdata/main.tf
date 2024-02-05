module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.0"

  bucket = "test-bucket"
  acl    = "private"

  control_object_ownership = true
  object_ownership         = "ObjectWriter"

  versioning = {
    enabled = true
  }
}

module "ec2_instance" {
  source = "./modules/ec2"
  
  instance_type = "t3.micro"

  user_data = "test"
}