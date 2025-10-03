terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.84.0"
    }
  }

  required_version = ">= 1.2.0"

  backend "s3" {  
    bucket       = "bulkintel-bucket"  
    key          = "terraform/statefile.tfstate"  
    region       = "il-central-1"  
    encrypt      = true  
    use_lockfile = true  #S3 native locking
  }  
}

provider "aws" {
  region  = "il-central-1"
}