-- 默认角色种子（设计文档 §31，schema.md §201）：admin / operator / viewer。
-- 首次引导（setup，T-20）依赖 admin 角色存在；INSERT OR IGNORE 保证幂等。
INSERT OR IGNORE INTO roles (id, name, description) VALUES
    ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa20', 'admin', 'full access'),
    ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa21', 'operator', 'nodes/routes read+write'),
    ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa22', 'viewer', 'read-only');
