const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'sua-chave-secreta-aqui';

// --- Setup do Upload ---
const UPLOADS_DIR = './uploads';
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname.replace(/\s/g, '_'));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Apenas arquivos .doc e .docx são permitidos.'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB
  fileFilter: fileFilter
});


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
    if (err) return;
    const users = [
      { username: 'admin', password: 'admin123', name: 'Administrador', user_type: 'admin' },
      { username: 'departamento_pessoal', password: 'senha123', name: 'Departamento Pessoal', user_type: 'department' },
      { username: 'departamento_legalizacao', password: 'senha123', name: 'Departamento Legalização', user_type: 'department' },
      { username: 'departamento_contabil', password: 'senha123', name: 'Departamento Contábil', user_type: 'department' },
      { username: 'departamento_financeiro', password: 'senha123', name: 'Departamento Financeiro', user_type: 'department' },
      { username: 'departamento_fiscal', password: 'senha123', name: 'Departamento Fiscal', user_type: 'department' }
    ];
    const stmt = db.prepare(`INSERT OR IGNORE INTO users (username, password, name, user_type) VALUES (?, ?, ?, ?);`);
    users.forEach(user => {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(user.password, salt);
      stmt.run(user.username, hash, user.name, user.user_type);
    });
    stmt.finalize();
  });

  db.run(`CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, room_location TEXT NOT NULL, date TEXT NOT NULL,
    start_time TEXT NOT NULL, end_time TEXT NOT NULL, subject TEXT NOT NULL, organizer_id INTEGER NOT NULL,
    department TEXT NOT NULL, participants INTEGER NOT NULL, participants_names TEXT,
    file_path TEXT,
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

const canManageMeetings = (req, res, next) => {
    if (req.user.user_type !== 'admin' && req.user.user_type !== 'department') {
        return res.status(403).json({ error: 'Acesso negado. Você não tem permissão para gerenciar reuniões.' });
    }
    next();
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

// ✨ ROTA CORRIGIDA: Lógica de filtragem prematura no SQL foi removida. ✨
app.get('/api/meetings', authenticateToken, (req, res) => {
  const { statusFiltro } = req.query;
  // A query agora busca TODAS as reuniões, como deveria.
  const query = `SELECT m.*, u.name as organizer_name FROM meetings m JOIN users u ON m.organizer_id = u.id WHERE m.status != 'excluida' ORDER BY m.date, m.start_time;`;
  
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
    
    // A lógica de privacidade em JavaScript agora funciona corretamente, pois recebe todas as reuniões.
    const finalMeetings = processedMeetings.map(meeting => {
        const user = req.user;

        if (user.user_type === 'admin') {
            return { ...meeting, department: departmentMap.get(meeting.department) || meeting.department };
        }

        if (user.user_type === 'department') {
            const userDepartment = user.username.split('_')[1];
            const isOwnerDepartment = userDepartment === meeting.department;
            const isOrganizer = user.id === meeting.organizer_id;

            if (isOwnerDepartment || isOrganizer) {
                return { ...meeting, department: departmentMap.get(meeting.department) || meeting.department };
            }
        }
        
        return {
            ...meeting,
            subject: 'Reservado',
            organizer_name: 'Reservado',
            participants_names: null,
            department: 'Reservado',
            file_path: null
        };
    });
    
    res.json(finalMeetings);
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
    const { dataInicio, dataFim, sala, status, departamento } = queryParams;
    let query = `
        SELECT m.*, u.name as organizer_name
        FROM meetings m JOIN users u ON m.organizer_id = u.id
    `;
    const conditions = [];
    const params = [];

    if (dataInicio) { conditions.push('m.date >= ?'); params.push(dataInicio); }
    if (dataFim) { conditions.push('m.date <= ?'); params.push(dataFim); }
    if (sala && sala !== 'todas') { conditions.push('m.room_location = ?'); params.push(sala); }
    if (departamento && departamento !== 'todos') { conditions.push('m.department = ?'); params.push(departamento); }
    
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
              const normalizedStatus = m.status_display
                  .normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(' ', '_');
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
            const normalizedStatus = m.status_display.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(' ', '_');
            return normalizedStatus === statusFilter;
        });
      }

      const headers = ['Data', 'Hora Início', 'Hora Fim', 'Sala', 'Departamento', 'Assunto', 'Organizador', 'Participantes', 'Status', 'Anexo'];
      let csv = headers.join(';') + '\r\n';
      meetingsWithDeptName.forEach(m => {
          const row = [
            m.date ? new Date(m.date + 'T00:00:00').toLocaleDateString('pt-BR') : '', m.start_time || '', m.end_time || '',
            m.room_location === 'baixo' ? 'Sala de Baixo' : 'Sala de Cima', m.department || '',
            `"${(m.subject || '').replace(/"/g, '""')}"`, `"${(m.organizer_name || '').replace(/"/g, '""')}"`,
            `"${(m.participants_names || '').replace(/"/g, '""')}"`, m.status_display || '',
            m.file_path ? 'Sim' : 'Não'
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
              const normalizedStatus = m.status_display.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(' ', '_');
              return normalizedStatus === statusFilter;
          });
        }

        let html = `
          <html lang="pt-BR"><head><meta charset="UTF-8" /><title>Relatório de Reuniões</title><style>body{font-family:Arial,sans-serif;background:#f4f4f4;color:#333;margin:20px}h2{text-align:center;color:#111}table{width:100%;border-collapse:collapse;background:white;box-shadow:0 2px 5px rgba(0,0,0,.1)}th,td{padding:12px 15px;border:1px solid #ddd;text-align:left}th{background:#222;color:#ffc107;text-transform:uppercase}tr:nth-child(even){background:#f9f9f9}tr:hover{background:#f1f1f1}</style></head>
          <body><h2>Relatório de Reuniões</h2><table><thead><tr><th>Data</th><th>Horário</th><th>Sala</th><th>Departamento</th><th>Assunto</th><th>Organizador</th><th>Participantes</th><th>Status</th><th>Anexo</th></tr></thead><tbody>`;
        meetingsWithDeptName.forEach(m => {
            html += `<tr><td>${m.date ? new Date(m.date + 'T00:00:00').toLocaleDateString('pt-BR') : ''}</td><td>${m.start_time || ''} - ${m.end_time || ''}</td><td>${m.room_location === 'baixo' ? 'Sala de Baixo' : 'Sala de Cima'}</td><td>${m.department || ''}</td><td>${m.subject || ''}</td><td>${m.organizer_name || ''}</td><td>${m.participants_names || ''}</td><td>${m.status_display || ''}</td><td>${m.file_path ? 'Sim' : 'Não'}</td></tr>`;
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

app.post('/api/meetings', authenticateToken, canManageMeetings, upload.single('attachment'), checkConflict, (req, res) => {
  const { room_location, date, start_time, end_time, subject, participants_names } = req.body;
  
  const participants = parseInt(req.body.participants, 10);
  if (isNaN(participants) || participants < 1) {
    return res.status(400).json({ error: 'O número de participantes é inválido.' });
  }

  const department = (req.user.user_type === 'department') 
    ? req.user.username.split('_')[1] 
    : req.body.department;
    
  const filePath = req.file ? req.file.path : null;

  db.run(`INSERT INTO meetings (room_location, date, start_time, end_time, subject, organizer_id, participants, participants_names, department, file_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
    [room_location, date, start_time, end_time, subject, req.user.id, participants, participants_names, department, filePath],
    function (err) {
      if (err) {
        console.error("Erro no DB ao criar reunião:", err.message);
        return res.status(500).json({ error: 'Erro ao criar reunião.' });
      }
      res.status(201).json({ message: 'Reunião criada com sucesso!', id: this.lastID });
    }
  );
});

app.put('/api/meetings/:id', authenticateToken, canManageMeetings, upload.single('attachment'), checkConflict, (req, res) => {
  const { id } = req.params;
  const { room_location, date, start_time, end_time, subject, participants_names } = req.body;
  
  const participants = parseInt(req.body.participants, 10);
  if (isNaN(participants) || participants < 1) {
    return res.status(400).json({ error: 'O número de participantes é inválido.' });
  }

  const department = (req.user.user_type === 'department')
    ? req.user.username.split('_')[1]
    : req.body.department;

  db.get('SELECT file_path FROM meetings WHERE id = ?', [id], (err, meeting) => {
    if (err) return res.status(500).json({ error: 'Erro ao buscar anexo antigo.' });

    const newFilePath = req.file ? req.file.path : meeting.file_path;
    
    if (req.file && meeting.file_path) {
      fs.unlink(path.join(__dirname, meeting.file_path), (unlinkErr) => {
        if (unlinkErr) console.error("Erro ao deletar anexo antigo:", unlinkErr);
      });
    }

    db.run(`UPDATE meetings SET room_location = ?, date = ?, start_time = ?, end_time = ?, subject = ?, participants = ?, participants_names = ?, department = ?, file_path = ? WHERE id = ?;`,
      [room_location, date, start_time, end_time, subject, participants, participants_names, department, newFilePath, id], (err) => {
        if (err) {
          console.error("Erro no DB ao atualizar reunião:", err.message);
          return res.status(500).json({ error: 'Erro ao atualizar reunião.' });
        }
        res.json({ message: 'Reunião atualizada com sucesso!' });
      }
    );
  });
});

app.get('/api/meetings/:id/attachment', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.get('SELECT * FROM meetings WHERE id = ?', [id], (err, meeting) => {
    if (err) return res.status(500).json({ error: 'Erro no servidor.' });
    if (!meeting || !meeting.file_path) return res.status(404).json({ error: 'Anexo não encontrado.' });
    
    const userDept = req.user.user_type === 'department' ? req.user.username.split('_')[1] : null;
    const isOrganizer = req.user.id === meeting.organizer_id;
    const isAdminUser = req.user.user_type === 'admin';
    const isInvolvedDept = userDept && userDept === meeting.department;
    const isParticipant = (meeting.participants_names || '').includes(req.user.name);

    if (isAdminUser || isOrganizer || isInvolvedDept || isParticipant) {
      const filePath = path.join(__dirname, meeting.file_path);
      if (fs.existsSync(filePath)) {
        res.download(filePath);
      } else {
        res.status(404).json({ error: 'Arquivo físico não encontrado no servidor.' });
      }
    } else {
      res.status(403).json({ error: 'Você não tem permissão para baixar este anexo.' });
    }
  });
});

app.put('/api/meetings/:id/cancel', authenticateToken, canManageMeetings, (req, res) => {
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