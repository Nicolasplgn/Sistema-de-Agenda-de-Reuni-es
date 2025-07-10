# Sistema de Agenda - Salas de Reunião

Sistema completo para agendamento de salas de reunião com autenticação de usuários e controle de acesso.

## Funcionalidades

### 👥 Tipos de Usuário
- **Usuário Normal**: Pode agendar reuniões e ver apenas suas próprias reuniões
- **Administrador**: Pode ver todas as reuniões e seus assuntos, com acesso completo

### 🏢 Salas Disponíveis
- **Sala de Baixo**
- **Sala de Cima**

### ✨ Recursos
- Autenticação segura com JWT
- Banco de dados SQLite
- Validação de conflitos de horário
- Interface responsiva
- Campos obrigatórios (incluindo assunto da reunião)
- CRUD completo de reuniões

## 🚀 Instalação

### Pré-requisitos
- Node.js (versão 14 ou superior)
- npm ou yarn

### Passos para Instalação

1. **Clone ou baixe os arquivos do projeto**

2. **Instale as dependências**
```bash
npm install
```

3. **Execute o servidor**
```bash
npm start
```

4. **Acesse o sistema**
- Abra o navegador e vá para: `http://localhost:3001`

## 👤 Usuários Padrão

O sistema já vem com usuários criados para teste:

### Administrador
- **Usuário**: `admin`
- **Senha**: `admin123`
- **Permissões**: Ver todas as reuniões e assuntos

### Usuário Normal
- **Usuário**: `user`
- **Senha**: `user123`
- **Permissões**: Ver apenas suas próprias reuniões

## 📁 Estrutura de Arquivos

```
projeto/
├── server.js           # Servidor backend
├── package.json        # Dependências do projeto
├── meetings.db         # Banco de dados (criado automaticamente)
├── public/
│   └── index.html      # Interface do usuário
└── README.md          # Este arquivo
```

## 🔧 Configuração

### Variáveis de Ambiente (Opcional)
- `PORT`: Porta do servidor (padrão: 3001)
- `JWT_SECRET`: Chave secreta para JWT (padrão: fornecida)

### Banco de Dados
- O banco SQLite é criado automaticamente
- Localização: `./meetings.db`
- Tabelas: `users`, `meetings`

## 🚀 Deploy em Servidor

### Opções de Deploy

1. **VPS/Servidor Dedicado**
   - Copie os arquivos para o servidor
   - Execute `npm install`
   - Use PM2 para manter o processo ativo:
   ```bash
   npm install -g pm2
   pm2 start server.js --name "agenda-reuniao"
   ```

2. **Heroku**
   - Adicione um `Procfile`:
   ```
   web: node server.js
   ```

3. **DigitalOcean/AWS**
   - Configure um droplet/instância
   - Execute os comandos de instalação

### Configuração de Produção

1. **Altere a chave JWT**
   ```bash
   export JWT_SECRET="sua-chave-secreta-super-segura"
   ```

2. **Configure proxy reverso (Nginx)**
   ```nginx
   server {
       listen 80;
       server_name seu-dominio.com;
       
       location / {
           proxy_pass http://localhost:3001;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

## 📋 Uso do Sistema

### Para Usuários Normais
1. Faça login com suas credenciais
2. Escolha uma sala (Baixo ou Cima)
3. Clique em "Nova Reunião"
4. Preencha todos os campos obrigatórios
5. Salve a reunião

### Para Administradores
1. Acesso completo a todas as reuniões
2. Pode ver assuntos de todas as reuniões
3. Pode editar/excluir qualquer reunião

## 🛠️ Desenvolvimento

### Modo de Desenvolvimento
```bash
npm run dev
```

### Estrutura do Banco
```sql
-- Tabela de usuários
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    user_type TEXT NOT NULL DEFAULT 'normal'
);

-- Tabela de reuniões
CREATE TABLE meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_location TEXT NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    subject TEXT NOT NULL,
    organizer_id INTEGER NOT NULL,
    participants INTEGER NOT NULL,
    FOREIGN KEY (organizer_id) REFERENCES users (id)
);
```

## 🔒 Segurança

- Senhas criptografadas com bcrypt
- Autenticação JWT
- Validação de permissões
- Sanitização de dados

## 📱 Responsividade

- Interface adaptável para desktop e mobile
- Layout responsivo com CSS Grid
- Compatível com todos os navegadores modernos

## 🐛 Solução de Problemas

### Erro de Porta em Uso
```bash
# Verificar processos na porta 3001
lsof -i :3001

# Matar processo se necessário
kill -9 [PID]
```

### Problemas com Banco de Dados
- Exclua o arquivo `meetings.db` para recriar
- Verifique permissões de escrita na pasta

### Problemas de Login
- Verifique se os usuários padrão existem
- Confirme se a senha está correta

## 📞 Suporte

Para problemas ou dúvidas:
1. Verifique os logs do servidor
2. Confirme se todas as dependências estão instaladas
3. Teste com os usuários padrão primeiro