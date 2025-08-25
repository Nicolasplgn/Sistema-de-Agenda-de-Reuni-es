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
app.use(express.static('public'));

const db = new sqlite3.Database('./meetings.db', (err) => {
  if (err) console.error('Erro ao conectar ao banco de dados:', err.message);
  else console.log('Conectado ao banco de dados SQLite');
});

// --- Definição dos Departamentos ---
const departmentsList = [
    { id: 'pessoal', name: 'Departamento Pessoal' },
    { id: 'legalizacao', name: 'Departamento Legalização' },
    { id: 'contabil', name: 'Departamento Contábil' },
    { id: 'financeiro', name: 'Departamento Financeiro' },
    { id: 'fiscal', name: 'Departamento Fiscal' },
    { id: 'rh', name: 'RH' }
];
const departmentMap = new Map(departmentsList.map(d => [d.id, d.name]));


db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    user_type TEXT NOT NULL DEFAULT 'viewer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_location TEXT NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    subject TEXT NOT NULL,
    organizer_id INTEGER NOT NULL,
    department TEXT NOT NULL,
    participants INTEGER NOT NULL,
    participants_names TEXT,
    status TEXT NOT NULL DEFAULT 'pendente',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organizer_id) REFERENCES users(id)
  );`, () => {
      db.run("SELECT status FROM meetings LIMIT 1", (err) => {
          if (err) {
              db.run("ALTER TABLE meetings ADD COLUMN status TEXT NOT NULL DEFAULT 'pendente'");
          }
      });
  });
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

app.get('/api/meetings', authenticateToken, (req, res) => {
  const { status } = req.query;
  let query = `
    SELECT 
      m.*, 
      u.name as organizer_name,
      CASE 
        WHEN m.status = 'excluida' THEN 'excluida'
        WHEN datetime(m.date || ' ' || m.end_time) < datetime('now', 'localtime') THEN 'concluida' 
        ELSE 'pendente' 
      END as computed_status
    FROM meetings m 
    JOIN users u ON m.organizer_id = u.id
  `;
  const params = [];

  let whereClauses = [];
  if (status === 'pendente') {
    whereClauses.push("datetime(m.date || ' ' || m.end_time) >= datetime('now', 'localtime')");
    whereClauses.push("m.status = 'pendente'");
  } else if (status === 'concluida') {
    whereClauses.push("datetime(m.date || ' ' || m.end_time) < datetime('now', 'localtime')");
    whereClauses.push("m.status = 'pendente'");
  } else {
    whereClauses.push("m.status != 'excluida'");
  }
  
  if(whereClauses.length > 0) {
    query += ' WHERE ' + whereClauses.join(' AND ');
  }

  query += ' ORDER BY m.date, m.start_time;';
  
  db.all(query, params, (err, meetings) => {
    if (err) return res.status(500).json({ error: 'Erro ao carregar reuniões' });
    
    if (req.user.user_type === 'viewer') {
      const sanitizedMeetings = meetings.map(meeting => ({
        ...meeting,
        subject: 'Reservado',
        department: 'N/A',
        organizer_name: 'N/A',
        participants_names: null
      }));
      return res.json(sanitizedMeetings);
    }
    
    const meetingsWithDeptName = meetings.map(m => ({
        ...m,
        department: departmentMap.get(m.department) || m.department
    }));

    res.json(meetingsWithDeptName);
  });
});

function buildReportQuery(queryParams) {
    const { dataInicio, dataFim, sala } = queryParams;
    let query = `
        SELECT 
            m.id, m.date, m.start_time, m.end_time, m.room_location, m.department,
            m.subject, u.name as organizer_name, m.participants_names,
            CASE 
                WHEN m.status = 'excluida' THEN 'Excluída'
                WHEN datetime(m.date || ' ' || m.end_time) < datetime('now', 'localtime') THEN 'Concluída'
                ELSE 'Pendente'
            END as status_display
        FROM meetings m
        JOIN users u ON m.organizer_id = u.id
    `;
    const conditions = [];
    const params = [];

    if (dataInicio) { conditions.push('m.date >= ?'); params.push(dataInicio); }
    if (dataFim) { conditions.push('m.date <= ?'); params.push(dataFim); }
    if (sala && sala !== 'todas') { conditions.push('m.room_location = ?'); params.push(sala); }
    
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY m.date DESC, m.start_time DESC;';
    return { query, params };
}

app.get('/api/meetings/historico', authenticateToken, isAdmin, (req, res) => {
    const { query, params } = buildReportQuery(req.query);
    db.all(query, params, (err, meetings) => {
      if (err) return res.status(500).json({ error: 'Erro no banco de dados ao gerar relatório' });
      
      const meetingsWithDeptName = meetings.map(m => ({
          ...m,
          department: departmentMap.get(m.department) || m.department
      }));
      res.json(meetingsWithDeptName);
    });
});

// --- ROTA DE EXPORTAÇÃO CSV CORRIGIDA ---
app.get('/api/meetings/exportar', authenticateToken, isAdmin, (req, res) => {
    const { query, params } = buildReportQuery(req.query);
    db.all(query, params, (err, meetings) => {
      if (err) {
          console.error("Erro no banco de dados ao exportar CSV:", err);
          return res.status(500).json({ error: 'Erro no banco de dados ao exportar' });
      }
      
      const headers = ['Data', 'Hora Início', 'Hora Fim', 'Sala', 'Departamento', 'Assunto', 'Organizador', 'Participantes', 'Status'];
      let csv = headers.join(';') + '\r\n';
      
      try {
        meetings.forEach(m => {
          const row = [
            m.date ? new Date(m.date + 'T00:00:00').toLocaleDateString('pt-BR') : '',
            m.start_time || '',
            m.end_time || '',
            m.room_location === 'baixo' ? 'Sala de Baixo' : 'Sala de Cima',
            departmentMap.get(m.department) || m.department || '',
            `"${(m.subject || '').replace(/"/g, '""')}"`,
            `"${(m.organizer_name || '').replace(/"/g, '""')}"`,
            `"${(m.participants_names || '').replace(/"/g, '""')}"`,
            m.status_display || ''
          ];
          csv += row.join(';') + '\r\n';
        });
        
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename=relatorio_reunioes.csv');
        res.send(Buffer.from(csv, 'utf-8'));
      } catch(e) {
          console.error("Erro ao gerar string CSV para exportação:", e);
          res.status(500).json({ error: 'Erro interno no servidor ao gerar o arquivo CSV.' });
      }
    });
});

// --- ROTA DE EXPORTAÇÃO HTML ---
app.get('/api/meetings/exportar_html', authenticateToken, isAdmin, (req, res) => {
    const { query, params } = buildReportQuery(req.query);
    db.all(query, params, (err, meetings) => {
      if (err) {
        console.error("Erro no banco de dados ao exportar HTML:", err);
        return res.status(500).json({ error: 'Erro no banco de dados ao exportar' });
      }

      try {
        let html = `
          <html lang="pt-BR">
          <head>
            <meta charset="UTF-8" />
            <title>Relatório de Reuniões</title>
            <style>
              body { font-family: Arial, sans-serif; background: #f4f4f4; color: #333; margin: 20px; }
              h2 { text-align: center; color: #111; }
              table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
              th, td { padding: 12px 15px; border: 1px solid #ddd; text-align: left; }
              th { background: #222; color: #ffc107; text-transform: uppercase; }
              tr:nth-child(even) { background: #f9f9f9; }
              tr:hover { background: #f1f1f1; }
            </style>
          </head>
          <body>
            <h2>Relatório de Reuniões</h2>
            <table>
              <thead>
                <tr>
                  <th>Data</th>
                  <th>Horário</th>
                  <th>Sala</th>
                  <th>Departamento</th>
                  <th>Assunto</th>
                  <th>Organizador</th>
                  <th>Participantes</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
        `;

        meetings.forEach(m => {
          html += `
            <tr>
              <td>${m.date ? new Date(m.date + 'T00:00:00').toLocaleDateString('pt-BR') : ''}</td>
              <td>${m.start_time || ''} - ${m.end_time || ''}</td>
              <td>${m.room_location === 'baixo' ? 'Sala de Baixo' : 'Sala de Cima'}</td>
              <td>${departmentMap.get(m.department) || m.department || ''}</td>
              <td>${m.subject || ''}</td>
              <td>${m.organizer_name || ''}</td>
              <td>${m.participants_names || ''}</td>
              <td>${m.status_display || ''}</td>
            </tr>
          `;
        });

        html += `
              </tbody>
            </table>
          </body>
          </html>
        `;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename=relatorio_reunioes.html');
        res.send(html);
      } catch (e) {
        console.error("Erro ao gerar string HTML para exportação:", e);
        res.status(500).json({ error: 'Erro interno no servidor ao gerar o arquivo HTML.' });
      }
    });
});


app.get('/api/meetings/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const query = `SELECT m.* FROM meetings m WHERE m.id = ?;`;
  db.get(query, [id], (err, meeting) => {
    if (err) return res.status(500).json({ error: 'Erro ao buscar reunião.' });
    if (!meeting) return res.status(404).json({ error: 'Reunião não encontrada.' });
    
    if (req.user.user_type === 'viewer') {
        meeting.subject = 'Reservado';
        meeting.department = 'N/A';
        meeting.participants_names = null;
    }

    res.json(meeting);
  });
});

const checkConflict = (req, res, next) => {
  const { room_location, date, start_time, end_time } = req.body;
  const meetingIdToExclude = req.params.id || -1;
  const conflictQuery = `
    SELECT id FROM meetings 
    WHERE room_location = ? AND date = ? AND id != ? AND status = 'pendente' AND start_time < ? AND end_time > ?
  `;
  db.get(conflictQuery, [room_location, date, meetingIdToExclude, end_time, start_time], (err, row) => {
    if (err) return res.status(500).json({ error: 'Erro ao verificar conflitos.' });
    if (row) return res.status(409).json({ error: 'Conflito de horário! Já existe uma reunião agendada neste período para a sala selecionada.' });
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
  db.run(`UPDATE meetings SET room_location = ?, date = ?, start_time = ?, end_time = ?, subject = ?, participants = ?, participants_names = ?, department = ? WHERE id = ? AND status = 'pendente';`,
    [room_location, date, start_time, end_time, subject, participants, participants_names, department, id], (err) => {
      if (err) return res.status(500).json({ error: 'Erro ao atualizar reunião.' });
      res.json({ message: 'Reunião atualizada com sucesso!' });
    }
  );
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
  console.log('Fechando servidor...');
  server.close(() => {
    console.log('Servidor fechado.');
    db.close((err) => {
      if (err) console.error('Erro ao fechar banco de dados:', err.message);
      else console.log('Conexão com o banco encerrada.');
      process.exit(0);
    });
  });
});