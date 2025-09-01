const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'sua-chave-secreta-aqui';

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));


const db = new sqlite3.Database('./meetings.db', (err) => {
  if (err) console.error('Erro ao conectar ao banco de dados:', err.message);
  else console.log('Conectado ao banco de dados SQLite');
});

// --- Definição dos Departamentos ---
const departmentsList = [
    { id: 'pessoal', name: 'Departamento Pessoal' }, { id: 'legalizacao', name: 'Departamento Legalização' },
    { id: 'contabil', name: 'Departamento Contábil' }, { id: 'financeiro', name: 'Departamento Financeiro' },
    { id: 'fiscal', name: 'Departamento Fiscal' }, { id: 'rh', name: 'RH' }
];
const departmentMap = new Map(departmentsList.map(d => [d.id, d.name]));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    name TEXT NOT NULL, user_type TEXT NOT NULL DEFAULT 'viewer', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`, (err) => {
    if (!err) {
      const users = [
        { username: 'admin', password: 'admin123', name: 'Administrador', user_type: 'admin' },
        { username: 'visualizador', password: 'visual123', name: 'Usuário Visualizador', user_type: 'viewer' }
      ];
      const stmt = db.prepare(`INSERT OR IGNORE INTO users (username, password, name, user_type) VALUES (?, ?, ?, ?);`);
      users.forEach(user => {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(user.password, salt);
        stmt.run(user.username, hash, user.name, user.user_type);
      });
      stmt.finalize();
    }
  });

  db.run(`CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, room_location TEXT NOT NULL, date TEXT NOT NULL,
    start_time TEXT NOT NULL, end_time TEXT NOT NULL, subject TEXT NOT NULL, organizer_id INTEGER NOT NULL,
    department TEXT NOT NULL, participants INTEGER NOT NULL, participants_names TEXT,
    status TEXT NOT NULL DEFAULT 'pendente', created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organizer_id) REFERENCES users(id)
  );`);
});

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token de acesso requerido' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
    if (req.user.user_type !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Recurso exclusivo para administradores.' });
    }
    next();
};

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
  db.get('SELECT * FROM users WHERE username = ?;', [username], (err, user) => {
    if (err) return res.status(500).json({ error: 'Erro no servidor' });
    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Credenciais inválidas' });
    const token = jwt.sign({ id: user.id, username: user.username, name: user.name, user_type: user.user_type }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, name: user.name, user_type: user.user_type, username: user.username } });
  });
});

app.get('/api/departments', authenticateToken, (req, res) => {
  res.json(departmentsList);
});

// Rota de Reuniões com Lógica de Status Aprimorada
app.get('/api/meetings', authenticateToken, (req, res) => {
  const { statusFiltro } = req.query;
  let query = `SELECT m.*, u.name as organizer_name FROM meetings m JOIN users u ON m.organizer_id = u.id`;
  
  if (req.user.user_type === 'viewer') {
    query += " WHERE m.status != 'excluida'";
  }

  query += ' ORDER BY m.date, m.start_time;';
  
  db.all(query, [], (err, meetings) => {
    if (err) return res.status(500).json({ error: 'Erro ao carregar reuniões' });
    
    const now = new Date();
    let processedMeetings = meetings.map(m => {
        const startDateTime = new Date(`${m.date}T${m.start_time}`);
        const endDateTime = new Date(`${m.date}T${m.end_time}`);
        let computed_status = 'pendente';

        if (m.status === 'cancelada') computed_status = 'cancelada';
        else if (m.status === 'excluida') computed_status = 'excluida';
        else if (now >= startDateTime && now <= endDateTime) computed_status = 'em_andamento';
        else if (now > endDateTime) computed_status = 'concluida';
        
        return { ...m, computed_status };
    });

    if (statusFiltro) {
        processedMeetings = processedMeetings.filter(m => m.computed_status === statusFiltro);
    }
    
    if (req.user.user_type === 'viewer') {
      processedMeetings = processedMeetings.map(m => ({
        ...m,
        subject: 'Reservado', department: 'N/A',
        organizer_name: 'N/A', participants_names: null
      }));
    } else {
        processedMeetings = processedMeetings.map(m => ({
            ...m, department: departmentMap.get(m.department) || m.department
        }));
    }
    res.json(processedMeetings.filter(m => m.computed_status !== 'excluida'));
  });
});

function getStatusDisplay(meeting) {
    const now = new Date();
    const startDateTime = new Date(`${meeting.date}T${meeting.start_time}`);
    const endDateTime = new Date(`${meeting.date}T${meeting.end_time}`);

    if (meeting.status === 'cancelada') return 'Cancelada';
    if (meeting.status === 'excluida') return 'Excluída';
    if (now >= startDateTime && now <= endDateTime) return 'Em Andamento';
    if (now > endDateTime) return 'Concluída';
    return 'Pendente';
}

function buildReportQuery(queryParams) {
    const { dataInicio, dataFim, sala, status } = queryParams;
    let query = `
        SELECT m.*, u.name as organizer_name
        FROM meetings m JOIN users u ON m.organizer_id = u.id
    `;
    const conditions = [];
    const params = [];

    if (dataInicio) { conditions.push('m.date >= ?'); params.push(dataInicio); }
    if (dataFim) { conditions.push('m.date <= ?'); params.push(dataFim); }
    if (sala && sala !== 'todas') { conditions.push('m.room_location = ?'); params.push(sala); }
    
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY m.date DESC, m.start_time DESC;';
    return { query, params, statusFilter: status };
}

app.get('/api/meetings/historico', authenticateToken, isAdmin, (req, res) => {
    const { query, params, statusFilter } = buildReportQuery(req.query);
    db.all(query, params, (err, meetings) => {
      if (err) return res.status(500).json({ error: 'Erro no banco de dados ao gerar relatório' });
      
      let meetingsWithDeptName = meetings.map(m => ({
          ...m,
          department: departmentMap.get(m.department) || m.department,
          status_display: getStatusDisplay(m)
      }));

      if (statusFilter && statusFilter !== 'todos') {
          meetingsWithDeptName = meetingsWithDeptName.filter(m => {
              // ✨ CORREÇÃO APLICADA AQUI ✨
              const normalizedStatus = m.status_display
                  .normalize("NFD") // Decompõe caracteres acentuados (ex: 'í' -> 'i' + '´')
                  .replace(/[\u0300-\u036f]/g, "") // Remove os acentos
                  .toLowerCase()
                  .replace(' ', '_');
              return normalizedStatus === statusFilter;
          });
      }
      
      res.json(meetingsWithDeptName);
    });
});

app.get('/api/meetings/exportar', authenticateToken, isAdmin, (req, res) => {
    const { query, params, statusFilter } = buildReportQuery(req.query);
    db.all(query, params, (err, meetings) => {
      if (err) return res.status(500).json({ error: 'Erro no banco de dados ao exportar' });
      
      let meetingsWithDeptName = meetings.map(m => ({
          ...m, department: departmentMap.get(m.department) || m.department, status_display: getStatusDisplay(m)
      }));
      
      if (statusFilter && statusFilter !== 'todos') {
        meetingsWithDeptName = meetingsWithDeptName.filter(m => {
            // ✨ CORREÇÃO APLICADA AQUI ✨
            const normalizedStatus = m.status_display
                .normalize("NFD")
                .replace(/[\u0300-\u036f]/g, "")
                .toLowerCase()
                .replace(' ', '_');
            return normalizedStatus === statusFilter;
        });
      }

      const headers = ['Data', 'Hora Início', 'Hora Fim', 'Sala', 'Departamento', 'Assunto', 'Organizador', 'Participantes', 'Status'];
      let csv = headers.join(';') + '\r\n';
      meetingsWithDeptName.forEach(m => {
          const row = [
            m.date ? new Date(m.date + 'T00:00:00').toLocaleDateString('pt-BR') : '', m.start_time || '', m.end_time || '',
            m.room_location === 'baixo' ? 'Sala de Baixo' : 'Sala de Cima', m.department || '',
            `"${(m.subject || '').replace(/"/g, '""')}"`, `"${(m.organizer_name || '').replace(/"/g, '""')}"`,
            `"${(m.participants_names || '').replace(/"/g, '""')}"`, m.status_display || ''
          ];
          csv += row.join(';') + '\r\n';
      });
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename=relatorio_reunioes.csv');
      res.send(Buffer.from(csv, 'utf-8'));
    });
});


app.get('/api/meetings/exportar_html', authenticateToken, isAdmin, (req, res) => {
    const { query, params, statusFilter } = buildReportQuery(req.query);
    db.all(query, params, (err, meetings) => {
        if (err) return res.status(500).json({ error: 'Erro ao exportar HTML' });

        let meetingsWithDeptName = meetings.map(m => ({
            ...m, department: departmentMap.get(m.department) || m.department, status_display: getStatusDisplay(m)
        }));

        if(statusFilter && statusFilter !== 'todos'){
          meetingsWithDeptName = meetingsWithDeptName.filter(m => {
              // ✨ CORREÇÃO APLICADA AQUI ✨
              const normalizedStatus = m.status_display
                  .normalize("NFD")
                  .replace(/[\u0300-\u036f]/g, "")
                  .toLowerCase()
                  .replace(' ', '_');
              return normalizedStatus === statusFilter;
          });
        }

        let html = `
          <html lang="pt-BR"><head><meta charset="UTF-8" /><title>Relatório de Reuniões</title><style>body{font-family:Arial,sans-serif;background:#f4f4f4;color:#333;margin:20px}h2{text-align:center;color:#111}table{width:100%;border-collapse:collapse;background:white;box-shadow:0 2px 5px rgba(0,0,0,.1)}th,td{padding:12px 15px;border:1px solid #ddd;text-align:left}th{background:#222;color:#ffc107;text-transform:uppercase}tr:nth-child(even){background:#f9f9f9}tr:hover{background:#f1f1f1}</style></head>
          <body><h2>Relatório de Reuniões</h2><table><thead><tr><th>Data</th><th>Horário</th><th>Sala</th><th>Departamento</th><th>Assunto</th><th>Organizador</th><th>Participantes</th><th>Status</th></tr></thead><tbody>`;
        meetingsWithDeptName.forEach(m => {
            html += `<tr><td>${m.date ? new Date(m.date + 'T00:00:00').toLocaleDateString('pt-BR') : ''}</td><td>${m.start_time || ''} - ${m.end_time || ''}</td><td>${m.room_location === 'baixo' ? 'Sala de Baixo' : 'Sala de Cima'}</td><td>${m.department || ''}</td><td>${m.subject || ''}</td><td>${m.organizer_name || ''}</td><td>${m.participants_names || ''}</td><td>${m.status_display || ''}</td></tr>`;
        });
        html += `</tbody></table></body></html>`;
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename=relatorio_reunioes.html');
        res.send(html);
    });
});

app.get('/api/meetings/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.get(`SELECT m.* FROM meetings m WHERE m.id = ?;`, [id], (err, meeting) => {
    if (err) return res.status(500).json({ error: 'Erro ao buscar reunião.' });
    if (!meeting) return res.status(404).json({ error: 'Reunião não encontrada.' });
    if (req.user.user_type === 'viewer') {
        meeting.subject = 'Reservado'; meeting.department = 'N/A';
        meeting.participants_names = null;
    }
    res.json(meeting);
  });
});

const checkConflict = (req, res, next) => {
  const { room_location, date, start_time, end_time } = req.body;
  const meetingIdToExclude = req.params.id || -1;
  const conflictQuery = `SELECT id FROM meetings WHERE room_location = ? AND date = ? AND id != ? AND status = 'pendente' AND start_time < ? AND end_time > ?`;
  db.get(conflictQuery, [room_location, date, meetingIdToExclude, end_time, start_time], (err, row) => {
    if (err) return res.status(500).json({ error: 'Erro ao verificar conflitos.' });
    if (row) return res.status(409).json({ error: 'Conflito de horário! Já existe uma reunião agendada neste período.' });
    next();
  });
};

app.post('/api/meetings', authenticateToken, isAdmin, checkConflict, (req, res) => {
  const { room_location, date, start_time, end_time, subject, participants, participants_names, department } = req.body;
  db.run(`INSERT INTO meetings (room_location, date, start_time, end_time, subject, organizer_id, participants, participants_names, department) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
    [room_location, date, start_time, end_time, subject, req.user.id, participants, participants_names, department],
    function (err) {
      if (err) return res.status(500).json({ error: 'Erro ao criar reunião.' });
      res.status(201).json({ message: 'Reunião criada com sucesso!', id: this.lastID });
    }
  );
});

app.put('/api/meetings/:id', authenticateToken, isAdmin, checkConflict, (req, res) => {
  const { id } = req.params;
  const { room_location, date, start_time, end_time, subject, participants, participants_names, department } = req.body;
  db.run(`UPDATE meetings SET room_location = ?, date = ?, start_time = ?, end_time = ?, subject = ?, participants = ?, participants_names = ?, department = ? WHERE id = ?;`,
    [room_location, date, start_time, end_time, subject, participants, participants_names, department, id], (err) => {
      if (err) return res.status(500).json({ error: 'Erro ao atualizar reunião.' });
      res.json({ message: 'Reunião atualizada com sucesso!' });
    }
  );
});

app.put('/api/meetings/:id/cancel', authenticateToken, isAdmin, (req, res) => {
  const { id } = req.params;
  db.run(`UPDATE meetings SET status = 'cancelada' WHERE id = ? AND status = 'pendente';`, [id], function(err) {
      if (err) return res.status(500).json({ error: 'Erro ao cancelar reunião.' });
      if (this.changes === 0) return res.status(404).json({ error: 'Reunião não encontrada ou já finalizada.' });
      res.json({ message: 'Reunião cancelada com sucesso!' });
  });
});

app.delete('/api/meetings/:id', authenticateToken, isAdmin, (req, res) => {
  const { id } = req.params;
  db.run(`UPDATE meetings SET status = 'excluida' WHERE id = ?;`, [id], function (err) {
    if (err) return res.status(500).json({ error: 'Erro ao excluir reunião.' });
    if (this.changes === 0) return res.status(404).json({ error: 'Reunião não encontrada.' });
    res.json({ message: 'Reunião marcada como excluída!' });
  });
});

app.get('/api/verify', authenticateToken, (req, res) => res.json({ user: req.user }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const server = app.listen(PORT, '0.0.0.0', () => console.log(`Servidor rodando na porta ${PORT}`));
process.on('SIGINT', () => {
  server.close(() => { db.close(); process.exit(0); });
});