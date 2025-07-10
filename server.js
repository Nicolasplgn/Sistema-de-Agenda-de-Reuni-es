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

// Configuração do banco de dados
const db = new sqlite3.Database('./meetings.db', (err) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados:', err.message);
  } else {
    console.log('Conectado ao banco de dados SQLite');
  }
});

// Inicialização do banco de dados
db.serialize(() => {
  // Criação da tabela de usuários
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    user_type TEXT NOT NULL DEFAULT 'normal',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`, (err) => {
    if (err) {
      console.error('Erro ao criar tabela users:', err.message);
    }
  });

 // Criação da tabela de reuniões

db.run(`CREATE TABLE IF NOT EXISTS meetings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_location TEXT NOT NULL,
  date TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  subject TEXT NOT NULL,
  organizer_id INTEGER NOT NULL,
  participants INTEGER NOT NULL,
  participants_names TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organizer_id) REFERENCES users(id)
);`, (err) => {
  if (err) {
    console.error('Erro ao criar tabela meetings:', err.message);
  }
});



 
  // Inserção de usuários iniciais
  const users = [
    { username: 'admin', password: 'admin123', name: 'Administrador', user_type: 'admin' },
    { username: 'departamento_pessoal', password: '123', name: 'Departamento Pessoal', user_type: 'normal' },
    { username: 'departamento_legalizacao', password: '123', name: 'Departamento Legalização', user_type: 'normal' },
    { username: 'departamento_contabil', password: '123', name: 'Departamento Contábil', user_type: 'normal' },
    { username: 'departamento_financeiro', password: '123', name: 'Departamento Financeiro', user_type: 'normal' },
    { username: 'departamento_fiscal', password: '123', name: 'Departamento Fiscal', user_type: 'normal' },
  ];

  users.forEach(user => {
    const hashed = bcrypt.hashSync(user.password, 10);
    db.run(
      `INSERT OR IGNORE INTO users (username, password, name, user_type) VALUES (?, ?, ?, ?);`,
      [user.username, hashed, user.name, user.user_type],
      (err) => {
        if (err) {
          console.error(`Erro ao inserir usuário ${user.username}:`, err.message);
        }
      }
    );
  });
});

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token de acesso requerido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Rota de login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuário e senha são obrigatórios' });
  }

  db.get('SELECT * FROM users WHERE username = ?;', [username], (err, user) => {
    if (err) {
      console.error('Erro ao buscar usuário:', err);
      return res.status(500).json({ error: 'Erro no servidor' });
    }

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        name: user.name, 
        user_type: user.user_type 
      }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        user_type: user.user_type
      }
    });
  });
});

// Rota para obter reuniões
app.get('/api/meetings', authenticateToken, (req, res) => {
  const { room_location, date } = req.query;
  let query = `
    SELECT 
      m.id,
      m.room_location,
      m.date,
      m.start_time,
      m.end_time,
      CASE 
        WHEN m.organizer_id = ? OR ? = 'admin' THEN m.subject
        ELSE 'Reservado'
      END as subject,
      m.participants,
      m.organizer_id,
      u.name as organizer_name
    FROM meetings m 
    JOIN users u ON m.organizer_id = u.id
  `;
  
  const params = [req.user.id, req.user.user_type];
  
  // Filtros opcionais
  const conditions = [];
  if (room_location) {
    conditions.push('m.room_location = ?');
    params.push(room_location);
  }
  if (date) {
    conditions.push('m.date = ?');
    params.push(date);
  }
  
  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  
  query += ' ORDER BY m.date, m.start_time;';

  db.all(query, params, (err, meetings) => {
    if (err) {
      console.error('Erro ao buscar reuniões:', err);
      return res.status(500).json({ error: 'Erro ao buscar reuniões' });
    }
    res.json(meetings);
  });
});

// Rota para exportar relatório em CSV
app.get('/api/meetings/exportar', authenticateToken, (req, res) => {
  if (req.user.user_type !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  const { dataInicio, dataFim, sala } = req.query;

  let query = `
    SELECT 
      m.date as Data,
      m.start_time as 'Hora Início',
      m.end_time as 'Hora Fim',
      CASE 
        WHEN m.room_location = 'baixo' THEN 'Sala de Baixo'
        ELSE 'Sala de Cima'
      END as Sala,
      m.subject as Assunto,
      u.name as Organizador,
      m.participants as 'Quantidade Participantes',
      m.participants_names as 'Nomes Participantes'
    FROM meetings m 
    JOIN users u ON m.organizer_id = u.id
  `;

  const conditions = [];
  const params = [];

  if (dataInicio) {
    conditions.push('m.date >= ?');
    params.push(dataInicio);
  }

  if (dataFim) {
    conditions.push('m.date <= ?');
    params.push(dataFim);
  }

  if (sala && sala !== 'todas') {
    conditions.push('m.room_location = ?');
    params.push(sala);
  }

  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }

  query += ' ORDER BY m.date DESC, m.start_time DESC;';

  db.all(query, params, (err, meetings) => {
    if (err) {
      console.error('Erro ao exportar relatório:', err);
      return res.status(500).json({ error: 'Erro ao exportar relatório' });
    }

    let csv = 'Data;Hora Início;Hora Fim;Sala;Assunto;Organizador;Quantidade Participantes;Nomes Participantes\r\n';
    meetings.forEach(m => {
      csv += `"${m.Data}";"${m['Hora Início']}";"${m['Hora Fim']}";"${m.Sala}";"${m.Assunto}";"${m.Organizador}";"${m['Quantidade Participantes']}";"${m['Nomes Participantes']}"\r\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=relatorio_reunioes.csv');
    res.send(csv);
  });
});



// Rota para histórico de reuniões (apenas admin)
app.get('/api/meetings/historico', authenticateToken, (req, res) => {
  if (req.user.user_type !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  const { dataInicio, dataFim, sala } = req.query;
  let query = `
    SELECT m.*, u.name as organizer_name 
    FROM meetings m 
    JOIN users u ON m.organizer_id = u.id
  `;
  
  const conditions = [];
  const params = [];
  
  if (dataInicio) {
    conditions.push('m.date >= ?');
    params.push(dataInicio);
  }
  
  if (dataFim) {
    conditions.push('m.date <= ?');
    params.push(dataFim);
  }
  
  if (sala && sala !== 'todas') {
    conditions.push('m.room_location = ?');
    params.push(sala);
  }
  
  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  
  query += ' ORDER BY m.date DESC, m.start_time DESC;';
  
  db.all(query, params, (err, meetings) => {
    if (err) {
      console.error('Erro ao buscar histórico:', err);
      return res.status(500).json({ error: 'Erro ao buscar histórico' });
    }
    res.json(meetings);
  });
});

// Rota para criar nova reunião
app.post('/api/meetings', authenticateToken, (req, res) => {
  const { room_location, date, start_time, end_time, subject, participants, participants_names } = req.body;
  
  // Validação básica
  if (!room_location || !date || !start_time || !end_time || !subject || !participants) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
  }
  
  if (!participants_names || participants_names.split(',').length !== participants) {
  return res.status(400).json({ error: 'Forneça os nomes de todos os participantes' });
}

  // Validação de horário
  if (start_time >= end_time) {
    return res.status(400).json({ error: 'O horário de término deve ser após o horário de início' });
  }

  // Validação dos participantes
  if (participants < 1) {
    return res.status(400).json({ error: 'Deve haver pelo menos 1 participante' });
  }

  if (participants > 20) { // Ajuste conforme necessário
    return res.status(400).json({ error: 'Número máximo de participantes é 20' });
  }

  // Verificar se os nomes dos participantes foram fornecidos
  if (!participants_names || participants_names.split(',').length !== participants) {
    return res.status(400).json({ error: 'Forneça os nomes de todos os participantes' });
  }

  // Verificar conflitos de horário
  db.get(`
    SELECT COUNT(*) as count 
    FROM meetings 
    WHERE room_location = ? 
      AND date = ? 
      AND (
        (start_time < ? AND end_time > ?) OR 
        (start_time < ? AND end_time > ?) OR
        (start_time >= ? AND end_time <= ?)
      );
  `, [
    room_location, date, 
    start_time, start_time, 
    end_time, end_time,
    start_time, end_time
  ], (err, result) => {
    if (err) {
      console.error('Erro ao verificar conflitos:', err);
      return res.status(500).json({ error: 'Erro ao verificar conflitos' });
    }
    
    if (result.count > 0) {
      return res.status(400).json({ error: 'Conflito de horário com outra reunião nesta sala' });
    }

    // Criar a reunião com os nomes dos participantes
    db.run(
      `INSERT INTO meetings (
        room_location, date, start_time, end_time, 
        subject, organizer_id, participants, participants_names
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);`,
      [
        room_location, 
        date, 
        start_time, 
        end_time, 
        subject, 
        req.user.id, 
        participants,
        participants_names
      ],
      function (err) {
        if (err) {
          console.error('Erro ao criar reunião:', err);
          return res.status(500).json({ error: 'Erro ao criar reunião' });
        }
        
        // Obter os dados completos da reunião criada
        db.get(
          `SELECT m.*, u.name as organizer_name 
           FROM meetings m
           JOIN users u ON m.organizer_id = u.id
           WHERE m.id = ?`,
          [this.lastID],
          (err, meeting) => {
            if (err) {
              console.error('Erro ao buscar reunião criada:', err);
              return res.status(500).json({ error: 'Erro ao recuperar dados da reunião' });
            }
            
            res.json({ 
              message: 'Reunião criada com sucesso', 
              id: this.lastID,
              meeting: meeting
            });
          }
        );
      }
    );
  });
});

// Rota para atualizar reunião
app.put('/api/meetings/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { room_location, date, start_time, end_time, subject, participants } = req.body;
  
  // Validação básica
  if (!room_location || !date || !start_time || !end_time || !subject || !participants) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
  }
  
  // Validação de horário
  if (start_time >= end_time) {
    return res.status(400).json({ error: 'O horário de término deve ser após o horário de início' });
  }

  // Primeiro verifica se a reunião existe e pertence ao usuário (a menos que seja admin)
  db.get(
    `SELECT * FROM meetings WHERE id = ? ${req.user.user_type !== 'admin' ? 'AND organizer_id = ?' : ''};`,
    req.user.user_type !== 'admin' ? [id, req.user.id] : [id],
    (err, meeting) => {
      if (err) {
        console.error('Erro ao buscar reunião:', err);
        return res.status(500).json({ error: 'Erro ao buscar reunião' });
      }
      if (!meeting) {
        return res.status(404).json({ error: 'Reunião não encontrada ou sem permissão' });
      }

      // Verificar conflitos de horário (excluindo a própria reunião)
      db.get(`
        SELECT COUNT(*) as count 
        FROM meetings 
        WHERE room_location = ? 
          AND date = ? 
          AND id != ?
          AND (
            (start_time < ? AND end_time > ?) OR 
            (start_time < ? AND end_time > ?) OR
            (start_time >= ? AND end_time <= ?)
          );
      `, [
        room_location, date, id,
        start_time, start_time, 
        end_time, end_time,
        start_time, end_time
      ], (err, result) => {
        if (err) {
          console.error('Erro ao verificar conflitos:', err);
          return res.status(500).json({ error: 'Erro ao verificar conflitos' });
        }
        
        if (result.count > 0) {
          return res.status(400).json({ error: 'Conflito de horário com outra reunião nesta sala' });
        }

        // Atualizar a reunião
        db.run(
          `UPDATE meetings SET 
            room_location = ?, 
            date = ?, 
            start_time = ?, 
            end_time = ?, 
            subject = ?, 
            participants = ?
          WHERE id = ? ${req.user.user_type !== 'admin' ? 'AND organizer_id = ?' : ''};`,
          req.user.user_type !== 'admin' 
            ? [room_location, date, start_time, end_time, subject, participants, id, req.user.id]
            : [room_location, date, start_time, end_time, subject, participants, id],
          function (err) {
            if (err) {
              console.error('Erro ao atualizar reunião:', err);
              return res.status(500).json({ error: 'Erro ao atualizar reunião' });
            }
            if (this.changes === 0) {
              return res.status(404).json({ error: 'Reunião não encontrada ou sem permissão' });
            }
            res.json({ message: 'Reunião atualizada com sucesso' });
          }
        );
      });
    }
  );
});

// Rota para deletar reunião
app.delete('/api/meetings/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  db.run(
    `DELETE FROM meetings 
    WHERE id = ? ${req.user.user_type !== 'admin' ? 'AND organizer_id = ?' : ''};`,
    req.user.user_type !== 'admin' ? [id, req.user.id] : [id],
    function (err) {
      if (err) {
        console.error('Erro ao deletar reunião:', err);
        return res.status(500).json({ error: 'Erro ao deletar reunião' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Reunião não encontrada ou sem permissão' });
      }
      res.json({ message: 'Reunião deletada com sucesso' });
    }
  );
});

// Rota para verificar token
app.get('/api/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// Servir o frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

// Encerrar conexão com o banco ao fechar o servidor
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Erro ao fechar banco de dados:', err.message);
    } else {
      console.log('Conexão com o banco encerrada.');
    }
    process.exit(0);
  });
});