variable "database_source" {
  description = "Intentionally broad sample source"
  default     = "0.0.0.0/0"
}

resource "aws_internet_gateway" "sample" {
  vpc_id = aws_vpc.sample.id
}

resource "aws_route" "sample_public" {
  route_table_id         = aws_route_table.sample_public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.sample.id
}

resource "aws_security_group" "sample_database" {
  name        = "sample-public-database"
  description = "Intentionally risky database sample"
  vpc_id      = aws_vpc.sample.id

  ingress {
    description = "Intentionally public PostgreSQL"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.database_source]
  }
}

resource "aws_db_instance" "sample" {
  publicly_accessible    = true
  vpc_security_group_ids = [aws_security_group.sample_database.id]
}
