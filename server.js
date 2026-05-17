const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
const SECRET_KEY = 'Wuyi1998.1014'; // 请修改为随机字符串

app.use(cors());
app.use(bodyParser.json());

// 数据库连接池
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'Wuyi1998.1014',   // 修改为实际密码
    database: 'accounting',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
const promisePool = pool.promise();

// ---------- 中间件：验证 JWT ----------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: '未登录' });
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: '登录已过期' });
        req.user = user;
        next();
    });
};

// ---------- 用户注册 ----------
// 手机号正则（简单校验11位数字，以1开头）
const phoneRegex = /^1[3-9]\d{9}$/;

// 密码复杂度正则：至少一个大写字母、一个小写字母、一个数字、一个特殊符号
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).+$/;

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    
    
    if (!username || !password) {
        return res.status(400).json({ error: '手机号和密码必填' });
    }
    // 验证手机号格式
    const phoneRegex = /^1[3-9]\d{9}$/;
    if (!phoneRegex.test(username)) {
        return res.status(400).json({ error: '请输入有效的11位手机号码' });
    }
    // 验证密码复杂度
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).+$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({ error: '密码必须包含大写字母、小写字母、数字和特殊符号' });
    }
    try {
        // 先查询是否已存在
        const [existing] = await promisePool.query('SELECT id FROM users WHERE username = ?', [username]);
        console.log('查询到已存在记录数:', existing.length);
        if (existing.length > 0) {
            return res.status(409).json({ error: '该手机号已注册' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await promisePool.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        console.log('插入成功, id:', result.insertId);
        res.status(201).json({ message: '注册成功' });
    } catch (err) {
        console.error('注册错误:', err);
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: '该手机号已注册' });
        }
        res.status(500).json({ error: err.message });
    }
});

// ---------- 用户登录 ----------
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码必填' });
    try {
        const [rows] = await promisePool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).json({ error: '用户名或密码错误' });
        const user = rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: '用户名或密码错误' });
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });
        res.json({ token, userId: user.id, username: user.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------- 获取分类列表 ----------
app.get('/api/categories', authenticateToken, async (req, res) => {
    try {
        const [rows] = await promisePool.query('SELECT * FROM categories ORDER BY type, id');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------- 获取记录（支持分类筛选）----------
app.get('/api/records', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { category_id } = req.query;
    let sql = `SELECT r.id, r.description, r.amount, r.type, DATE_FORMAT(r.date, '%Y-%m-%d') as date, r.category_id, c.name as category_name
               FROM records r
               LEFT JOIN categories c ON r.category_id = c.id
               WHERE r.user_id = ?`;
    const params = [userId];
    if (category_id) {
        sql += ` AND r.category_id = ?`;
        params.push(category_id);
    }
    sql += ` ORDER BY r.date DESC, r.created_at DESC`;
    try {
        const [rows] = await promisePool.query(sql, params);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------- 新增记录（带分类）----------
app.post('/api/records', authenticateToken, async (req, res) => {
    const { description, amount, type, date, category_id } = req.body;
    const userId = req.user.id;
    if (!description || !amount || !type || !date || !category_id) {
        return res.status(400).json({ error: '缺少必要字段' });
    }
    try {
        const [result] = await promisePool.query(
            `INSERT INTO records (description, amount, type, date, user_id, category_id)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [description, amount, type, date, userId, category_id]
        );
        res.status(201).json({ id: result.insertId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------- 删除记录 ----------
app.delete('/api/records/:id', authenticateToken, async (req, res) => {
    const recordId = req.params.id;
    const userId = req.user.id;
    try {
        const [result] = await promisePool.query('DELETE FROM records WHERE id = ? AND user_id = ?', [recordId, userId]);
        if (result.affectedRows === 0) return res.status(404).json({ error: '记录不存在' });
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------- 统计数据（收入、支出、余额）----------
app.get('/api/stats', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const [rows] = await promisePool.query(
            `SELECT SUM(CASE WHEN type='income' THEN amount ELSE 0 END) AS totalIncome,
                    SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS totalExpense
             FROM records WHERE user_id = ?`,
            [userId]
        );
        const totalIncome = Number(rows[0].totalIncome) || 0;
        const totalExpense = Number(rows[0].totalExpense) || 0;
        const balance = totalIncome - totalExpense;
        res.json({ totalIncome, totalExpense, balance });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------- 月度趋势统计（用于 ECharts）----------
app.get('/api/statistics/monthly', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const sql = `
        SELECT DATE_FORMAT(date, '%Y-%m') as month,
               SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as income,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as expense
        FROM records
        WHERE user_id = ? AND date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        GROUP BY month
        ORDER BY month ASC
    `;
    try {
        const [rows] = await promisePool.query(sql, [userId]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 注销账号（删除当前用户及其所有记账数据）
app.delete('/api/user', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        // 开启事务
        await promisePool.query('START TRANSACTION');
        // 删除该用户的所有记录
        await promisePool.query('DELETE FROM records WHERE user_id = ?', [userId]);
        // 删除用户
        const [result] = await promisePool.query('DELETE FROM users WHERE id = ?', [userId]);
        if (result.affectedRows === 0) {
            await promisePool.query('ROLLBACK');
            return res.status(404).json({ error: '用户不存在' });
        }
        await promisePool.query('COMMIT');
        res.status(200).json({ message: '账号已注销' });
    } catch (err) {
        await promisePool.query('ROLLBACK');
        console.error('注销失败:', err);
        res.status(500).json({ error: '注销失败，请稍后重试' });
    }
});

app.listen(port, () => {
    console.log(`后端服务运行在 http://localhost:${port}`);
});