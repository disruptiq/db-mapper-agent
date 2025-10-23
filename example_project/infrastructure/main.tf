# Terraform configuration for database infrastructure

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# RDS PostgreSQL instance
resource "aws_db_instance" "postgres" {
  identifier           = "myapp-db"
  engine               = "postgres"
  engine_version       = "13.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  storage_type         = "gp2"
  db_name              = "myapp"
  username             = "dbuser"
  password             = "dbpassword123"
  parameter_group_name = "default.postgres13"
  skip_final_snapshot  = true
  publicly_accessible  = false

  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name    = aws_db_subnet_group.db.name

  tags = {
    Name        = "myapp-postgres"
    Environment = "development"
  }
}

# RDS MySQL instance for analytics
resource "aws_db_instance" "mysql" {
  identifier           = "analytics-db"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  storage_type         = "gp2"
  db_name              = "analytics"
  username             = "analytics"
  password             = "analytics123"
  parameter_group_name = "default.mysql8.0"
  skip_final_snapshot  = true
  publicly_accessible  = false

  vpc_security_group_ids = [aws_security_group.db.id]
  db_subnet_group_name    = aws_db_subnet_group.db.name

  tags = {
    Name        = "analytics-mysql"
    Environment = "development"
  }
}

# ElastiCache Redis cluster
resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "myapp-redis"
  engine               = "redis"
  node_type            = "cache.t3.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis6.x"
  port                 = 6379

  tags = {
    Name        = "myapp-redis"
    Environment = "development"
  }
}

# DocumentDB (MongoDB-compatible)
resource "aws_docdb_cluster" "mongodb" {
  cluster_identifier      = "myapp-docdb"
  engine                  = "docdb"
  master_username         = "dbuser"
  master_password         = "dbpassword123"
  skip_final_snapshot     = true
  db_subnet_group_name    = aws_db_subnet_group.db.name
  vpc_security_group_ids  = [aws_security_group.db.id]

  tags = {
    Name        = "myapp-docdb"
    Environment = "development"
  }
}

resource "aws_docdb_cluster_instance" "mongodb" {
  identifier         = "myapp-docdb-instance"
  cluster_identifier = aws_docdb_cluster.mongodb.id
  instance_class     = "db.t3.medium"
}

# Security group for databases
resource "aws_security_group" "db" {
  name_prefix = "db-sg-"
  description = "Security group for database instances"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "PostgreSQL"
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "MySQL"
  }

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "Redis"
  }

  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "MongoDB"
  }
}

# DB subnet group
resource "aws_db_subnet_group" "db" {
  name       = "myapp-db-subnet"
  subnet_ids = ["subnet-12345", "subnet-67890"] # Replace with actual subnet IDs

  tags = {
    Name = "myapp-db-subnet"
  }
}
