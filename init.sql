-- =============================================================
-- 一次性初始化脚本：在你的 PostgreSQL 15 实例上执行一次
-- 用法：psql -U postgres -h 你的主机 -f init.sql
-- 表结构不需要手动建，认证服务启动时会自动创建（CREATE TABLE IF NOT EXISTS）
-- =============================================================

CREATE DATABASE auth_db;

-- 连入新库执行授权（PG15 中 public schema 默认只允许库 owner 建表）
\c auth_db

CREATE USER auth_user WITH PASSWORD '请改成强密码';

-- 数据库级授权
GRANT ALL PRIVILEGES ON DATABASE auth_db TO auth_user;
-- schema 级授权（建表必需）
GRANT ALL ON SCHEMA public TO auth_user;
