resource "aws_subnet" "bulkintel_subnet" {
  vpc_id = var.bulkintel_subnet.vpc_id
  cidr_block = var.bulkintel_subnet.cidr_block
  map_public_ip_on_launch = var.bulkintel_subnet.map_public_ip_on_launch
  tags = {
    Name = var.bulkintel_subnet.name
    Terraform = var.bulkintel_subnet.tag_terraform
  }
}

resource "aws_internet_gateway" "bulkintel_subnet_igw" {
  vpc_id = var.bulkintel_subnet.vpc_id
}

resource "aws_route_table" "bulkintel_subnet_rt" {
  vpc_id = var.bulkintel_subnet.vpc_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.bulkintel_subnet_igw.id
  }
}

resource "aws_route_table_association" "bulkintel_subnet_rta" {
  subnet_id = aws_subnet.bulkintel_subnet.id
  route_table_id = aws_route_table.bulkintel_subnet_rt.id
}