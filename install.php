<?php
/**
 * Script de Instalação - Condomínio Vitória Régia
 * 
 * Este script automatiza a instalação completa do sistema:
 * - Verificação de requisitos do servidor
 * - Criação do banco de dados
 * - Criação de tabelas
 * - Configuração inicial
 * - Criação do usuário administrador
 * - Dados de exemplo
 * - Configurações de segurança
 * 
 * IMPORTANTE: Remover este arquivo após a instalação!
 */

// Configurações de instalação
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Verificar se já foi instalado
if (file_exists('INSTALLED.lock')) {
    die('Sistema já foi instalado. Remova o arquivo INSTALLED.lock para reinstalar.');
}

// Configurar timeout para scripts longos
set_time_limit(300); // 5 minutos

// Estado da instalação
$step = $_GET['step'] ?? 1;
$errors = [];
$success = [];

// Processar formulário
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($step) {
        case 2:
            $result = processStep2();
            break;
        case 3:
            $result = processStep3();
            break;
        case 4:
            $result = processStep4();
            break;
    }
    
    if (isset($result) && $result['success']) {
        $success = $result['messages'];
        if ($step < 5) {
            header("Location: ?step=" . ($step + 1));
            exit;
        }
    } else {
        $errors = $result['errors'] ?? [];
    }
}

/**
 * Verificar requisitos do sistema
 */
function checkSystemRequirements() {
    $requirements = [
        'php_version' => [
            'name' => 'PHP 7.4+',
            'required' => true,
            'status' => version_compare(PHP_VERSION, '7.4.0', '>='),
            'current' => PHP_VERSION
        ],
        'pdo' => [
            'name' => 'PDO Extension',
            'required' => true,
            'status' => extension_loaded('pdo'),
            'current' => extension_loaded('pdo') ? 'Instalado' : 'Não instalado'
        ],
        'pdo_mysql' => [
            'name' => 'PDO MySQL Driver',
            'required' => true,
            'status' => extension_loaded('pdo_mysql'),
            'current' => extension_loaded('pdo_mysql') ? 'Instalado' : 'Não instalado'
        ],
        'gd' => [
            'name' => 'GD Extension (para imagens)',
            'required' => true,
            'status' => extension_loaded('gd'),
            'current' => extension_loaded('gd') ? 'Instalado' : 'Não instalado'
        ],
        'fileinfo' => [
            'name' => 'FileInfo Extension',
            'required' => true,
            'status' => extension_loaded('fileinfo'),
            'current' => extension_loaded('fileinfo') ? 'Instalado' : 'Não instalado'
        ],
        'openssl' => [
            'name' => 'OpenSSL Extension',
            'required' => true,
            'status' => extension_loaded('openssl'),
            'current' => extension_loaded('openssl') ? 'Instalado' : 'Não instalado'
        ],
        'mbstring' => [
            'name' => 'Mbstring Extension',
            'required' => true,
            'status' => extension_loaded('mbstring'),
            'current' => extension_loaded('mbstring') ? 'Instalado' : 'Não instalado'
        ],
        'json' => [
            'name' => 'JSON Extension',
            'required' => true,
            'status' => extension_loaded('json'),
            'current' => extension_loaded('json') ? 'Instalado' : 'Não instalado'
        ],
        'uploads_dir' => [
            'name' => 'Diretório uploads/ writável',
            'required' => true,
            'status' => is_writable('.') || @mkdir('uploads', 0755, true),
            'current' => is_writable('.') ? 'Writável' : 'Não writável'
        ],
        'logs_dir' => [
            'name' => 'Diretório logs/ writável',
            'required' => true,
            'status' => is_writable('.') || @mkdir('logs', 0755, true),
            'current' => is_writable('.') ? 'Writável' : 'Não writável'
        ],
        'memory_limit' => [
            'name' => 'Memory Limit (128M+)',
            'required' => false,
            'status' => (int)ini_get('memory_limit') >= 128 || ini_get('memory_limit') == -1,
            'current' => ini_get('memory_limit')
        ],
        'upload_max_filesize' => [
            'name' => 'Upload Max Filesize (5M+)',
            'required' => false,
            'status' => (int)ini_get('upload_max_filesize') >= 5,
            'current' => ini_get('upload_max_filesize')
        ]
    ];
    
    return $requirements;
}

/**
 * Processar Step 2 - Configuração do banco
 */
function processStep2() {
    $host = $_POST['db_host'] ?? 'localhost';
    $database = $_POST['db_name'] ?? 'extremes_cond_vitoria_regia';
    $username = $_POST['db_user'] ?? 'extremes_condvitoriaregia';
    $password = $_POST['db_pass'] ?? '(,;JmYvZjB0cEL0R';
    
    $errors = [];
    
    if (empty($username)) {
        $errors[] = 'Usuário do banco é obrigatório';
    }
    
    // Testar conexão
    try {
        $dsn = "mysql:host=$host;charset=utf8mb4";
        $pdo = new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]);
        
        // Criar banco se não existir
        $pdo->exec("CREATE DATABASE IF NOT EXISTS `$database` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $pdo->exec("USE `$database`");
        
        // Salvar configurações
        $configContent = generateConfigFile($host, $database, $username, $password);
        file_put_contents('config_generated.php', $configContent);
        
        return [
            'success' => true,
            'messages' => [
                'Conexão com banco estabelecida com sucesso',
                'Banco de dados criado: ' . $database,
                'Arquivo de configuração gerado'
            ]
        ];
        
    } catch (PDOException $e) {
        return [
            'success' => false,
            'errors' => ['Erro de conexão: ' . $e->getMessage()]
        ];
    }
}

/**
 * Processar Step 3 - Criar tabelas
 */
function processStep3() {
    try {
        // Carregar configuração
        if (!file_exists('config_generated.php')) {
            throw new Exception('Configuração não encontrada. Volte ao passo anterior.');
        }
        
        require_once 'config_generated.php';
        $pdo = getDB();
        
        // Executar scripts de criação de tabelas
        $sqlScripts = getSQLScripts();
        
        foreach ($sqlScripts as $name => $sql) {
            $pdo->exec($sql);
        }
        
        return [
            'success' => true,
            'messages' => [
                'Todas as tabelas foram criadas com sucesso',
                'Estrutura do banco configurada',
                'Índices de performance criados'
            ]
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'errors' => ['Erro ao criar tabelas: ' . $e->getMessage()]
        ];
    }
}

/**
 * Processar Step 4 - Configuração inicial
 */
function processStep4() {
    try {
        require_once 'config_generated.php';
        $pdo = getDB();
        
        // Dados do administrador
        $adminUser = $_POST['admin_user'] ?? 'admin';
        $adminPass = $_POST['admin_pass'] ?? '';
        $adminName = $_POST['admin_name'] ?? 'Administrador';
        $adminEmail = $_POST['admin_email'] ?? '';
        
        $createSampleData = isset($_POST['sample_data']);
        
        $errors = [];
        
        if (empty($adminPass)) {
            $errors[] = 'Senha do administrador é obrigatória';
        }
        
        if (strlen($adminPass) < 6) {
            $errors[] = 'Senha deve ter pelo menos 6 caracteres';
        }
        
        if (!empty($errors)) {
            return ['success' => false, 'errors' => $errors];
        }
        
        // Criar usuário administrador
        $passwordHash = password_hash($adminPass, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("
            INSERT INTO usuarios (username, password_hash, nome, email, ativo, created_at)
            VALUES (?, ?, ?, ?, 1, NOW())
        ");
        $stmt->execute([$adminUser, $passwordHash, $adminName, $adminEmail]);
        
        // Criar as 8 casas
        for ($i = 1; $i <= 8; $i++) {
            $stmt = $pdo->prepare("INSERT INTO casas (numero) VALUES (?)");
            $stmt->execute([$i]);
        }
        
        $messages = [
            'Usuário administrador criado',
            '8 casas inicializadas no sistema'
        ];
        
        // Criar dados de exemplo se solicitado
        if ($createSampleData) {
            createSampleData($pdo);
            $messages[] = 'Dados de exemplo criados';
        }
        
        // Criar diretórios necessários
        createDirectories();
        $messages[] = 'Diretórios de upload criados';
        
        // Criar arquivo de lock
        file_put_contents('INSTALLED.lock', date('Y-m-d H:i:s') . "\nInstalado com sucesso!");
        $messages[] = 'Arquivo de bloqueio criado';
        
        // Renomear config gerado para config.php
        if (file_exists('config_generated.php')) {
            rename('config_generated.php', 'config.php');
            $messages[] = 'Configuração ativada';
        }
        
        return [
            'success' => true,
            'messages' => $messages
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'errors' => ['Erro na configuração inicial: ' . $e->getMessage()]
        ];
    }
}

/**
 * Gerar arquivo de configuração
 */
function generateConfigFile($host, $database, $username, $password) {
    $template = file_get_contents('config.php');
    
    // Se não existir config.php template, usar o básico
    if (!$template) {
        $template = '<?php
// Configurações do Banco de Dados
define(\'DB_HOST\', \'{{HOST}}\');
define(\'DB_NAME\', \'{{DATABASE}}\');
define(\'DB_USER\', \'{{USERNAME}}\');
define(\'DB_PASS\', \'{{PASSWORD}}\');
define(\'DB_CHARSET\', \'utf8mb4\');

// Outras configurações...
define(\'DEBUG_MODE\', false);
define(\'SESSION_TIMEOUT\', 2 * 60 * 60);

// Função de conexão
function getDB() {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]);
    }
    return $pdo;
}
?>';
    }
    
    // Substituir placeholders
    $config = str_replace([
        'define(\'DB_HOST\', \'localhost\');',
        'define(\'DB_NAME\', \'condominio_vitoria_regia\');',
        'define(\'DB_USER\', \'seu_usuario\');',
        'define(\'DB_PASS\', \'sua_senha\');',
        '{{HOST}}',
        '{{DATABASE}}',
        '{{USERNAME}}',
        '{{PASSWORD}}'
    ], [
        "define('DB_HOST', '$host');",
        "define('DB_NAME', '$database');",
        "define('DB_USER', '$username');",
        "define('DB_PASS', '$password');",
        $host,
        $database,
        $username,
        $password
    ], $template);
    
    return $config;
}

/**
 * Obter scripts SQL para criação de tabelas
 */
function getSQLScripts() {
    return [
        'usuarios' => "
            CREATE TABLE usuarios (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                nome VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                ativo BOOLEAN DEFAULT TRUE,
                ultimo_login TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_username (username),
                INDEX idx_ativo (ativo)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'casas' => "
            CREATE TABLE casas (
                id INT PRIMARY KEY AUTO_INCREMENT,
                numero INT NOT NULL UNIQUE,
                morador VARCHAR(255),
                telefone VARCHAR(20),
                contrato_inicio DATE,
                contrato_fim DATE,
                valor_mensal DECIMAL(10,2) DEFAULT 0,
                arquivo_contrato VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_numero (numero),
                INDEX idx_morador (morador)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'pagamentos' => "
            CREATE TABLE pagamentos (
                id INT PRIMARY KEY AUTO_INCREMENT,
                casa_id INT NOT NULL,
                mes INT NOT NULL,
                ano INT NOT NULL,
                valor DECIMAL(10,2) NOT NULL,
                data_pagamento DATE,
                status ENUM('pendente', 'pago', 'atrasado') DEFAULT 'pendente',
                comprovante VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (casa_id) REFERENCES casas(id) ON DELETE CASCADE,
                UNIQUE KEY unique_pagamento (casa_id, mes, ano),
                INDEX idx_casa_periodo (casa_id, ano, mes),
                INDEX idx_status (status),
                INDEX idx_data_pagamento (data_pagamento)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'observacoes' => "
            CREATE TABLE observacoes (
                id INT PRIMARY KEY AUTO_INCREMENT,
                casa_id INT NOT NULL,
                descricao TEXT NOT NULL,
                data DATE NOT NULL,
                status ENUM('pendente', 'em_andamento', 'resolvida') DEFAULT 'pendente',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (casa_id) REFERENCES casas(id) ON DELETE CASCADE,
                INDEX idx_casa_data (casa_id, data),
                INDEX idx_status (status),
                INDEX idx_data (data)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'sessoes' => "
            CREATE TABLE sessoes (
                id VARCHAR(128) PRIMARY KEY,
                usuario_id INT NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                INDEX idx_usuario_expires (usuario_id, expires_at),
                INDEX idx_expires (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'login_attempts' => "
            CREATE TABLE login_attempts (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50),
                ip_address VARCHAR(45),
                success BOOLEAN DEFAULT FALSE,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_username_time (username, attempt_time),
                INDEX idx_ip_time (ip_address, attempt_time),
                INDEX idx_success_time (success, attempt_time)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'security_events' => "
            CREATE TABLE security_events (
                id INT PRIMARY KEY AUTO_INCREMENT,
                event_type VARCHAR(50) NOT NULL,
                username VARCHAR(50),
                ip_address VARCHAR(45),
                details TEXT,
                severity ENUM('info', 'warning', 'critical') DEFAULT 'info',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_event_time (event_type, created_at),
                INDEX idx_severity_time (severity, created_at),
                INDEX idx_ip_time (ip_address, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'rate_limits' => "
            CREATE TABLE rate_limits (
                id INT PRIMARY KEY AUTO_INCREMENT,
                identifier VARCHAR(100) NOT NULL,
                action VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_identifier_action_time (identifier, action, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'blocked_ips' => "
            CREATE TABLE blocked_ips (
                id INT PRIMARY KEY AUTO_INCREMENT,
                ip_address VARCHAR(45) NOT NULL UNIQUE,
                reason VARCHAR(100) NOT NULL,
                block_count INT DEFAULT 1,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_ip_expires (ip_address, expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'password_reset_tokens' => "
            CREATE TABLE password_reset_tokens (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                token VARCHAR(128) NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                INDEX idx_token (token),
                INDEX idx_expires (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        ",
        
        'file_access_logs' => "
            CREATE TABLE file_access_logs (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT NOT NULL,
                filename VARCHAR(255) NOT NULL,
                action ENUM('view', 'download', 'thumbnail') NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                INDEX idx_user_date (user_id, accessed_at),
                INDEX idx_filename (filename),
                INDEX idx_action_date (action, accessed_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        "
    ];
}

/**
 * Criar dados de exemplo
 */
function createSampleData($pdo) {
    // Atualizar algumas casas com moradores
    $stmt = $pdo->prepare("
        UPDATE casas SET 
            morador = ?, telefone = ?, contrato_inicio = ?, contrato_fim = ?, valor_mensal = ?
        WHERE numero = ?
    ");
    
    $casasExemplo = [
        [1, 'João Silva', '(11) 99999-1111', '2024-01-01', '2024-12-31', 1200.00],
        [2, 'Maria Santos', '(11) 99999-2222', '2024-02-01', '2025-01-31', 1150.00],
        [3, 'Carlos Oliveira', '(11) 99999-3333', '2024-03-01', '2025-02-28', 1300.00]
    ];
    
    foreach ($casasExemplo as $casa) {
        $stmt->execute([$casa[1], $casa[2], $casa[3], $casa[4], $casa[5], $casa[0]]);
    }
    
    // Criar alguns pagamentos de exemplo
    $stmt = $pdo->prepare("
        INSERT INTO pagamentos (casa_id, mes, ano, valor, data_pagamento, status)
        VALUES (?, ?, ?, ?, ?, ?)
    ");
    
    $pagamentosExemplo = [
        [1, 6, 2025, 1200.00, '2025-06-05', 'pago'],
        [1, 7, 2025, 1200.00, null, 'pendente'],
        [2, 6, 2025, 1150.00, '2025-06-10', 'pago'],
        [3, 6, 2025, 1300.00, null, 'atrasado']
    ];
    
    foreach ($pagamentosExemplo as $pagamento) {
        $stmt->execute($pagamento);
    }
    
    // Criar algumas observações de exemplo
    $stmt = $pdo->prepare("
        INSERT INTO observacoes (casa_id, descricao, data, status)
        VALUES (?, ?, ?, ?)
    ");
    
    $observacoesExemplo = [
        [1, 'Trocar fechadura da porta principal', '2025-06-15', 'pendente'],
        [2, 'Vazamento na pia da cozinha', '2025-06-10', 'resolvida'],
        [3, 'Pintura das paredes externas necessária', '2025-06-20', 'em_andamento']
    ];
    
    foreach ($observacoesExemplo as $observacao) {
        $stmt->execute($observacao);
    }
}

/**
 * Criar diretórios necessários
 */
function createDirectories() {
    $directories = [
        'uploads' => 0755,
        'uploads/contratos' => 0755,
        'uploads/comprovantes' => 0755,
        'uploads/comprovantes/thumbnails' => 0755,
        'logs' => 0755
    ];
    
    foreach ($directories as $dir => $permissions) {
        if (!is_dir($dir)) {
            mkdir($dir, $permissions, true);
        }
        
        // Criar .htaccess para uploads
        if (strpos($dir, 'uploads') === 0) {
            $htaccessContent = '# Proteção de segurança
php_flag engine off
AddHandler cgi-script .php .phtml .php3 .pl .py .jsp .asp .sh .cgi
Options -ExecCGI -Indexes

<Files ~ "\.(jpg|jpeg|png|pdf)$">
    Order allow,deny
    Allow from all
</Files>

<Files ~ "\.">
    Order allow,deny
    Deny from all
</Files>';
            
            file_put_contents($dir . '/.htaccess', $htaccessContent);
        }
    }
}

$requirements = checkSystemRequirements();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instalação - Condomínio Vitória Régia</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #2C5530 0%, #4A7C59 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .progress-bar {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
            padding: 0 20px;
        }

        .progress-step {
            flex: 1;
            text-align: center;
            padding: 10px;
            background: rgba(255,255,255,0.2);
            margin: 0 5px;
            border-radius: 5px;
            font-size: 14px;
        }

        .progress-step.active {
            background: rgba(255,255,255,0.3);
            font-weight: bold;
        }

        .progress-step.completed {
            background: rgba(40, 167, 69, 0.3);
        }

        .content {
            padding: 30px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #2C5530;
        }

        .form-control {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s ease;
        }

        .form-control:focus {
            outline: none;
            border-color: #2C5530;
            box-shadow: 0 0 0 3px rgba(44, 85, 48, 0.1);
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }

        .btn-primary {
            background: linear-gradient(135deg, #2C5530, #4A7C59);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(44, 85, 48, 0.4);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border-left: 4px solid #28a745;
        }

        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border-left: 4px solid #dc3545;
        }

        .alert-warning {
            background: #fff3cd;
            color: #856404;
            border-left: 4px solid #ffc107;
        }

        .requirements-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }

        .requirements-table th,
        .requirements-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }

        .requirements-table th {
            background: #f8f9fa;
            font-weight: 600;
        }

        .status-ok {
            color: #28a745;
            font-weight: bold;
        }

        .status-error {
            color: #dc3545;
            font-weight: bold;
        }

        .status-warning {
            color: #ffc107;
            font-weight: bold;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            margin: 15px 0;
        }

        .checkbox-group input {
            margin-right: 10px;
        }

        .final-info {
            background: #e7f3ff;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #007bff;
        }

        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .progress-bar {
                flex-direction: column;
            }
            
            .progress-step {
                margin: 2px 0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏡 Instalação do Sistema</h1>
            <p>Condomínio Vitória Régia - Sistema de Gerenciamento</p>
            
            <div class="progress-bar">
                <div class="progress-step <?php echo $step >= 1 ? 'active' : ''; ?> <?php echo $step > 1 ? 'completed' : ''; ?>">
                    1. Requisitos
                </div>
                <div class="progress-step <?php echo $step >= 2 ? 'active' : ''; ?> <?php echo $step > 2 ? 'completed' : ''; ?>">
                    2. Banco de Dados
                </div>
                <div class="progress-step <?php echo $step >= 3 ? 'active' : ''; ?> <?php echo $step > 3 ? 'completed' : ''; ?>">
                    3. Tabelas
                </div>
                <div class="progress-step <?php echo $step >= 4 ? 'active' : ''; ?> <?php echo $step > 4 ? 'completed' : ''; ?>">
                    4. Configuração
                </div>
                <div class="progress-step <?php echo $step >= 5 ? 'active' : ''; ?>">
                    5. Finalização
                </div>
            </div>
        </div>

        <div class="content">
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <strong>❌ Erros encontrados:</strong>
                    <ul style="margin: 10px 0 0 20px;">
                        <?php foreach ($errors as $error): ?>
                            <li><?php echo htmlspecialchars($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <?php if (!empty($success)): ?>
                <div class="alert alert-success">
                    <strong>✅ Sucesso:</strong>
                    <ul style="margin: 10px 0 0 20px;">
                        <?php foreach ($success as $message): ?>
                            <li><?php echo htmlspecialchars($message); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <?php if ($step == 1): ?>
                <!-- Step 1: Verificação de Requisitos -->
                <h3>📋 Verificação de Requisitos do Sistema</h3>
                <p>Verificando se o servidor atende aos requisitos mínimos para o sistema:</p>

                <table class="requirements-table">
                    <thead>
                        <tr>
                            <th>Requisito</th>
                            <th>Status</th>
                            <th>Atual</th>
                            <th>Obrigatório</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($requirements as $req): ?>
                            <tr>
                                <td><?php echo $req['name']; ?></td>
                                <td>
                                    <?php if ($req['status']): ?>
                                        <span class="status-ok">✅ OK</span>
                                    <?php elseif ($req['required']): ?>
                                        <span class="status-error">❌ ERRO</span>
                                    <?php else: ?>
                                        <span class="status-warning">⚠️ AVISO</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo $req['current']; ?></td>
                                <td><?php echo $req['required'] ? 'Sim' : 'Não'; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <?php
                $hasErrors = false;
                foreach ($requirements as $req) {
                    if ($req['required'] && !$req['status']) {
                        $hasErrors = true;
                        break;
                    }
                }
                ?>

                <?php if ($hasErrors): ?>
                    <div class="alert alert-danger">
                        <strong>❌ Requisitos não atendidos!</strong><br>
                        Corrija os itens marcados em vermelho antes de continuar.
                    </div>
                <?php else: ?>
                    <div class="alert alert-success">
                        <strong>✅ Todos os requisitos obrigatórios foram atendidos!</strong><br>
                        Você pode continuar com a instalação.
                    </div>
                    <a href="?step=2" class="btn btn-primary">➡️ Continuar para Configuração do Banco</a>
                <?php endif; ?>

            <?php elseif ($step == 2): ?>
                <!-- Step 2: Configuração do Banco de Dados -->
                <h3>🗄️ Configuração do Banco de Dados</h3>
                <p>Configure a conexão com o banco de dados MySQL:</p>

                <form method="POST">
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Host do Banco</label>
                            <input type="text" name="db_host" class="form-control" 
                                   value="localhost" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Nome do Banco</label>
                            <input type="text" name="db_name" class="form-control" 
                                   value="condominio_vitoria_regia" required>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Usuário do Banco</label>
                            <input type="text" name="db_user" class="form-control" 
                                   placeholder="Digite o usuário MySQL" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Senha do Banco</label>
                            <input type="password" name="db_pass" class="form-control" 
                                   placeholder="Digite a senha MySQL">
                        </div>
                    </div>

                    <div class="alert alert-warning">
                        <strong>⚠️ Atenção:</strong> O banco de dados será criado automaticamente se não existir. 
                        Certifique-se de que o usuário tem permissões para criar bancos de dados.
                    </div>

                    <button type="submit" class="btn btn-primary">🔗 Testar Conexão e Continuar</button>
                </form>

            <?php elseif ($step == 3): ?>
                <!-- Step 3: Criação de Tabelas -->
                <h3>📊 Criação das Tabelas</h3>
                <p>Agora vamos criar todas as tabelas necessárias no banco de dados:</p>

                <div class="alert alert-warning">
                    <strong>📋 Tabelas que serão criadas:</strong>
                    <ul style="margin: 10px 0 0 20px; columns: 2;">
                        <li>usuarios</li>
                        <li>casas</li>
                        <li>pagamentos</li>
                        <li>observacoes</li>
                        <li>sessoes</li>
                        <li>login_attempts</li>
                        <li>security_events</li>
                        <li>rate_limits</li>
                        <li>blocked_ips</li>
                        <li>password_reset_tokens</li>
                        <li>file_access_logs</li>
                    </ul>
                </div>

                <form method="POST">
                    <p>Clique no botão abaixo para criar todas as tabelas e índices necessários:</p>
                    <button type="submit" class="btn btn-primary">🔨 Criar Tabelas</button>
                </form>

            <?php elseif ($step == 4): ?>
                <!-- Step 4: Configuração Inicial -->
                <h3>⚙️ Configuração Inicial</h3>
                <p>Configure o usuário administrador e dados iniciais:</p>

                <form method="POST">
                    <h4>👤 Usuário Administrador</h4>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Nome de Usuário</label>
                            <input type="text" name="admin_user" class="form-control" 
                                   value="admin" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Nome Completo</label>
                            <input type="text" name="admin_name" class="form-control" 
                                   value="Administrador" required>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Email (opcional)</label>
                            <input type="email" name="admin_email" class="form-control" 
                                   placeholder="admin@condominiovitoriaregia.com">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Senha</label>
                            <input type="password" name="admin_pass" class="form-control" 
                                   placeholder="Digite uma senha forte" required>
                        </div>
                    </div>

                    <h4>🏠 Configuração do Condomínio</h4>
                    <div class="checkbox-group">
                        <input type="checkbox" name="sample_data" id="sample_data" checked>
                        <label for="sample_data">
                            <strong>Criar dados de exemplo</strong><br>
                            <small>Inclui 3 casas com moradores, alguns pagamentos e observações de exemplo</small>
                        </label>
                    </div>

                    <div class="alert alert-warning">
                        <strong>📝 O que será criado:</strong>
                        <ul style="margin: 10px 0 0 20px;">
                            <li>Usuário administrador com as credenciais informadas</li>
                            <li>8 casas inicializadas no sistema</li>
                            <li>Diretórios de upload com proteções de segurança</li>
                            <li>Dados de exemplo (se marcado)</li>
                            <li>Arquivo de bloqueio de instalação</li>
                        </ul>
                    </div>

                    <button type="submit" class="btn btn-primary">🚀 Finalizar Instalação</button>
                </form>

            <?php elseif ($step == 5): ?>
                <!-- Step 5: Instalação Concluída -->
                <h3>🎉 Instalação Concluída com Sucesso!</h3>

                <div class="final-info">
                    <h4>✅ Sistema instalado e configurado</h4>
                    <p>O Condomínio Vitória Régia está pronto para uso!</p>

                    <h5>📋 Informações importantes:</h5>
                    <ul>
                        <li><strong>URL do sistema:</strong> <a href="index.php">index.php</a></li>
                        <li><strong>Usuário padrão:</strong> admin</li>
                        <li><strong>Senha:</strong> A que você definiu no passo anterior</li>
                        <li><strong>Casas disponíveis:</strong> 8 casas numeradas de 1 a 8</li>
                    </ul>

                    <h5>🔒 Recomendações de Segurança:</h5>
                    <ul>
                        <li>❌ <strong>REMOVA ESTE ARQUIVO (install.php) IMEDIATAMENTE</strong></li>
                        <li>❌ Remova também o arquivo create_password.php se existir</li>
                        <li>✅ Configure HTTPS em produção</li>
                        <li>✅ Configure backups regulares do banco de dados</li>
                        <li>✅ Monitore os logs de segurança regularmente</li>
                        <li>✅ Altere a senha padrão após o primeiro login</li>
                    </ul>

                    <h5>📁 Estrutura de arquivos criada:</h5>
                    <ul>
                        <li>📂 uploads/contratos/ - Contratos de locação</li>
                        <li>📂 uploads/comprovantes/ - Comprovantes de pagamento</li>
                        <li>📂 logs/ - Logs do sistema</li>
                        <li>🔒 INSTALLED.lock - Arquivo de bloqueio</li>
                    </ul>
                </div>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="index.php" class="btn btn-primary" style="font-size: 18px; padding: 15px 30px;">
                        🏡 Acessar o Sistema
                    </a>
                </div>

                <div class="alert alert-danger">
                    <strong>⚠️ IMPORTANTE:</strong> Após acessar o sistema, volte aqui e delete os arquivos:
                    <ul style="margin: 10px 0 0 20px;">
                        <li><code>install.php</code> (este arquivo)</li>
                        <li><code>create_password.php</code> (se existir)</li>
                    </ul>
                    Estes arquivos representam riscos de segurança se mantidos em produção.
                </div>

            <?php endif; ?>
        </div>
    </div>

    <script>
        // Auto-focus no primeiro campo de cada formulário
        document.addEventListener('DOMContentLoaded', function() {
            const firstInput = document.querySelector('input[type="text"], input[type="password"]');
            if (firstInput) {
                firstInput.focus();
            }
        });

        // Validação de senha forte
        function validatePassword(password) {
            const minLength = password.length >= 8;
            const hasUpper = /[A-Z]/.test(password);
            const hasLower = /[a-z]/.test(password);
            const hasNumber = /\d/.test(password);
            const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\?]/.test(password);
            
            return minLength && hasUpper && hasLower && hasNumber;
        }

        // Adicionar validação em tempo real
        const passwordField = document.querySelector('input[name="admin_pass"]');
        if (passwordField) {
            passwordField.addEventListener('input', function() {
                const isStrong = validatePassword(this.value);
                this.style.borderColor = isStrong ? '#28a745' : '#dc3545';
            });
        }

        // Confirmação antes de enviar formulários importantes
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', function(e) {
                if (<?php echo $step; ?> === 3) {
                    if (!confirm('Tem certeza que deseja criar as tabelas? Esta ação não pode ser desfeita.')) {
                        e.preventDefault();
                    }
                }
            });
        });
    </script>
</body>
</html>

<?php
/*
==============================================
 INSTRUÇÕES PÓS-INSTALAÇÃO:
==============================================

1. SEGURANÇA CRÍTICA:
   - DELETE este arquivo (install.php) IMEDIATAMENTE após a instalação
   - DELETE create_password.php se existir
   - Verifique se config.php tem as credenciais corretas

2. CONFIGURAÇÃO DE PRODUÇÃO:
   - Configure HTTPS com certificado SSL
   - Configure firewall para bloquear portas desnecessárias
   - Configure backup automático do banco de dados
   - Configure monitoramento de logs

3. PRIMEIRO ACESSO:
   - Acesse index.php
   - Faça login com as credenciais criadas
   - Altere a senha padrão
   - Configure dados das casas conforme necessário

4. MANUTENÇÃO REGULAR:
   - Monitore logs em logs/
   - Verifique security_events no banco
   - Limpe arquivos antigos periodicamente
   - Atualize senhas regularmente

5. BACKUP RECOMENDADO:
   - Banco de dados: diariamente
   - Arquivos uploads/: semanalmente
   - Configurações: mensalmente

6. MONITORAMENTO:
   - Verificar login_attempts para ataques
   - Monitorar blocked_ips para IPs suspeitos
   - Acompanhar security_events críticos
   - Verificar file_access_logs para acessos

==============================================
 ESTRUTURA FINAL DO SISTEMA:
==============================================

condominio/
├── index.php              # Página principal
├── config.php             # Configuração (gerado)
├── auth.php               # Sistema de autenticação
├── security.php           # Funções de segurança
├── api.php                # API principal
├── login_api.php          # API de login
├── upload_comprovante.php # Upload de arquivos
├── view_comprovante.php   # Visualização de arquivos
├── uploads/               # Arquivos uploadados
│   ├── contratos/         # Contratos (.htaccess)
│   └── comprovantes/      # Comprovantes (.htaccess)
│       └── thumbnails/    # Miniaturas
├── logs/                  # Logs do sistema
├── INSTALLED.lock         # Bloqueio de instalação
└── [REMOVIDOS após instalação]
    ├── install.php        # ❌ REMOVER
    └── create_password.php # ❌ REMOVER

==============================================
 CREDENCIAIS PADRÃO CRIADAS:
==============================================

Usuário: admin (ou personalizado)
Senha: [definida durante instalação]
Permissões: Administrador total
Casas: 8 casas numeradas (1-8)

==============================================
*/
?>