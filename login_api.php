<?php
/**
 * API de Autenticação - Condomínio Vitória Régia
 * 
 * Esta API gerencia todas as operações de autenticação:
 * - Login de usuários
 * - Logout e logout de todas as sessões
 * - Verificação de status de login
 * - Alteração de senha
 * - Recuperação de senha
 * - Estatísticas de login
 * 
 * Endpoints disponíveis:
 * POST /login_api.php { action: "login", username: "", password: "", remember_me: false }
 * POST /login_api.php { action: "logout" }
 * POST /login_api.php { action: "check" }
 * POST /login_api.php { action: "change_password", current_password: "", new_password: "" }
 * POST /login_api.php { action: "logout_all" }
 * POST /login_api.php { action: "stats" }
 * POST /login_api.php { action: "forgot_password", email: "" }
 */

require_once 'config.php';
require_once 'auth.php';

// Configurar headers
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

// Tratar requisições OPTIONS (preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Permitir apenas método POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => 'Método não permitido. Use POST.',
        'code' => 405
    ]);
    exit;
}

// Obter dados da requisição
$input = file_get_contents('php://input');
$data = json_decode($input, true);

// Verificar se dados foram enviados
if (!$data || !isset($data['action'])) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => 'Dados inválidos. Ação não especificada.',
        'code' => 400
    ]);
    exit;
}

$action = $data['action'];

// Log da requisição
logActivity("Auth API Request: $action", 'INFO', [
    'ip' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
]);

try {
    $auth = new Auth();
    
    switch ($action) {
        case 'login':
            handleLogin($auth, $data);
            break;
            
        case 'logout':
            handleLogout($auth);
            break;
            
        case 'check':
            handleCheck($auth);
            break;
            
        case 'change_password':
            handleChangePassword($auth, $data);
            break;
            
        case 'logout_all':
            handleLogoutAll($auth);
            break;
            
        case 'stats':
            handleStats($auth);
            break;
            
        case 'forgot_password':
            handleForgotPassword($data);
            break;
            
        case 'reset_password':
            handleResetPassword($data);
            break;
            
        default:
            throw new Exception('Ação não reconhecida: ' . $action, 400);
    }
    
} catch (Exception $e) {
    $code = $e->getCode() ?: 500;
    http_response_code($code);
    
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'code' => $code
    ]);
    
    // Log do erro
    error_log("Auth API Error: " . $e->getMessage() . " - Action: $action");
}

/**
 * Gerenciar login
 */
function handleLogin($auth, $data) {
    // Validar dados obrigatórios
    if (empty($data['username']) || empty($data['password'])) {
        throw new Exception('Usuário e senha são obrigatórios', 400);
    }
    
    // Sanitizar entrada
    $username = trim($data['username']);
    $password = $data['password'];
    $rememberMe = isset($data['remember_me']) && $data['remember_me'] === true;
    
    // Validações básicas
    if (strlen($username) < 3) {
        throw new Exception('Nome de usuário deve ter pelo menos 3 caracteres', 400);
    }
    
    if (strlen($password) < 6) {
        throw new Exception('Senha deve ter pelo menos 6 caracteres', 400);
    }
    
    // Verificar rate limiting
    if (!checkRateLimit($_SERVER['REMOTE_ADDR'], 'login')) {
        throw new Exception('Muitas tentativas de login. Tente novamente em alguns minutos.', 429);
    }
    
    // Tentar fazer login
    $result = $auth->login($username, $password, $rememberMe);
    
    if ($result['success']) {
        // Login bem-sucedido
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'message' => $result['message'],
            'user' => $result['user'],
            'session_info' => [
                'expires_in' => SESSION_TIMEOUT,
                'remember_me' => $rememberMe
            ]
        ]);
    } else {
        // Login falhou
        incrementRateLimit($_SERVER['REMOTE_ADDR'], 'login');
        
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'error' => $result['message'],
            'code' => 401
        ]);
    }
}

/**
 * Gerenciar logout
 */
function handleLogout($auth) {
    $result = $auth->logout();
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => 'Logout realizado com sucesso.'
    ]);
}

/**
 * Verificar status de login
 */
function handleCheck($auth) {
    $isLoggedIn = $auth->isLoggedIn();
    $userInfo = $isLoggedIn ? $auth->getUserInfo() : null;
    
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'logged_in' => $isLoggedIn,
        'user' => $userInfo,
        'session_info' => $isLoggedIn ? [
            'time_remaining' => SESSION_TIMEOUT - (time() - ($_SESSION['last_activity'] ?? 0)),
            'expires_at' => date('Y-m-d H:i:s', ($_SESSION['last_activity'] ?? 0) + SESSION_TIMEOUT)
        ] : null
    ]);
}

/**
 * Alterar senha
 */
function handleChangePassword($auth, $data) {
    // Verificar se usuário está logado
    if (!$auth->isLoggedIn()) {
        throw new Exception('Você precisa estar logado para alterar a senha', 401);
    }
    
    // Validar dados
    if (empty($data['current_password']) || empty($data['new_password'])) {
        throw new Exception('Senha atual e nova senha são obrigatórias', 400);
    }
    
    // Validar força da nova senha
    $newPassword = $data['new_password'];
    $passwordValidation = validatePasswordStrength($newPassword);
    
    if (!$passwordValidation['valid']) {
        throw new Exception($passwordValidation['error'], 400);
    }
    
    // Verificar se nova senha é diferente da atual
    if ($data['current_password'] === $newPassword) {
        throw new Exception('A nova senha deve ser diferente da senha atual', 400);
    }
    
    // Tentar alterar senha
    $result = $auth->changePassword($data['current_password'], $newPassword);
    
    if ($result['success']) {
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'message' => 'Senha alterada com sucesso. Por segurança, faça login novamente.'
        ]);
        
        // Fazer logout para forçar novo login
        $auth->logout();
    } else {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $result['message'],
            'code' => 400
        ]);
    }
}

/**
 * Logout de todas as sessões
 */
function handleLogoutAll($auth) {
    // Verificar se usuário está logado
    if (!$auth->isLoggedIn()) {
        throw new Exception('Você precisa estar logado', 401);
    }
    
    if ($auth->logoutAllSessions()) {
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'message' => 'Logout realizado em todas as sessões com sucesso.'
        ]);
    } else {
        throw new Exception('Erro ao fazer logout de todas as sessões', 500);
    }
}

/**
 * Obter estatísticas de login
 */
function handleStats($auth) {
    // Verificar se usuário está logado
    if (!$auth->isLoggedIn()) {
        throw new Exception('Você precisa estar logado para ver as estatísticas', 401);
    }
    
    $stats = $auth->getLoginStats();
    
    if ($stats) {
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'data' => $stats
        ]);
    } else {
        throw new Exception('Erro ao obter estatísticas', 500);
    }
}

/**
 * Esqueci minha senha
 */
function handleForgotPassword($data) {
    if (empty($data['email'])) {
        throw new Exception('Email é obrigatório', 400);
    }
    
    $email = filter_var(trim($data['email']), FILTER_VALIDATE_EMAIL);
    if (!$email) {
        throw new Exception('Email inválido', 400);
    }
    
    // Verificar rate limiting para reset de senha
    if (!checkRateLimit($_SERVER['REMOTE_ADDR'], 'forgot_password')) {
        throw new Exception('Muitas tentativas de recuperação. Tente novamente em 1 hora.', 429);
    }
    
    try {
        $pdo = getDB();
        
        // Verificar se email existe
        $stmt = $pdo->prepare("SELECT id, username, nome FROM usuarios WHERE email = ? AND ativo = 1");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            // Gerar token de recuperação
            $token = generateSecureToken();
            $expiresAt = date('Y-m-d H:i:s', time() + 3600); // 1 hora
            
            // Salvar token no banco
            $stmt = $pdo->prepare("
                INSERT INTO password_reset_tokens (user_id, token, expires_at) 
                VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE token = VALUES(token), expires_at = VALUES(expires_at)
            ");
            $stmt->execute([$user['id'], $token, $expiresAt]);
            
            // Enviar email (simulado por enquanto)
            $resetLink = "https://" . $_SERVER['HTTP_HOST'] . "/reset_password.php?token=" . $token;
            
            // Aqui você integraria com um serviço de email real
            logActivity("Token de recuperação gerado para: {$user['username']}", 'INFO', [
                'email' => $email,
                'token' => $token,
                'link' => $resetLink
            ]);
            
            incrementRateLimit($_SERVER['REMOTE_ADDR'], 'forgot_password');
            
            // Por segurança, sempre retornar sucesso mesmo se email não existir
            http_response_code(200);
            echo json_encode([
                'success' => true,
                'message' => 'Se o email existir em nosso sistema, você receberá instruções para redefinir sua senha.',
                'debug_info' => DEBUG_MODE ? [
                    'reset_link' => $resetLink,
                    'token' => $token,
                    'expires_at' => $expiresAt
                ] : null
            ]);
        } else {
            // Email não encontrado, mas não revelar isso por segurança
            incrementRateLimit($_SERVER['REMOTE_ADDR'], 'forgot_password');
            
            http_response_code(200);
            echo json_encode([
                'success' => true,
                'message' => 'Se o email existir em nosso sistema, você receberá instruções para redefinir sua senha.'
            ]);
        }
        
    } catch (Exception $e) {
        error_log("Erro na recuperação de senha: " . $e->getMessage());
        throw new Exception('Erro interno. Tente novamente mais tarde.', 500);
    }
}

/**
 * Redefinir senha
 */
function handleResetPassword($data) {
    if (empty($data['token']) || empty($data['new_password'])) {
        throw new Exception('Token e nova senha são obrigatórios', 400);
    }
    
    // Validar força da nova senha
    $passwordValidation = validatePasswordStrength($data['new_password']);
    if (!$passwordValidation['valid']) {
        throw new Exception($passwordValidation['error'], 400);
    }
    
    try {
        $pdo = getDB();
        
        // Verificar token
        $stmt = $pdo->prepare("
            SELECT rt.user_id, u.username, u.email 
            FROM password_reset_tokens rt
            JOIN usuarios u ON rt.user_id = u.id
            WHERE rt.token = ? AND rt.expires_at > NOW() AND u.ativo = 1
        ");
        $stmt->execute([$data['token']]);
        $resetData = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$resetData) {
            throw new Exception('Token inválido ou expirado', 400);
        }
        
        // Atualizar senha
        $newPasswordHash = password_hash($data['new_password'], PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("UPDATE usuarios SET password_hash = ? WHERE id = ?");
        $stmt->execute([$newPasswordHash, $resetData['user_id']]);
        
        // Remover token usado
        $stmt = $pdo->prepare("DELETE FROM password_reset_tokens WHERE user_id = ?");
        $stmt->execute([$resetData['user_id']]);
        
        // Invalidar todas as sessões do usuário
        $stmt = $pdo->prepare("DELETE FROM sessoes WHERE usuario_id = ?");
        $stmt->execute([$resetData['user_id']]);
        
        logActivity("Senha redefinida via token: {$resetData['username']}", 'SECURITY');
        
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'message' => 'Senha redefinida com sucesso. Faça login com sua nova senha.'
        ]);
        
    } catch (Exception $e) {
        if ($e->getCode() === 400) {
            throw $e;
        }
        error_log("Erro na redefinição de senha: " . $e->getMessage());
        throw new Exception('Erro interno. Tente novamente mais tarde.', 500);
    }
}

/**
 * Validar força da senha
 */
function validatePasswordStrength($password) {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = "deve ter pelo menos 8 caracteres";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "deve conter pelo menos uma letra maiúscula";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "deve conter pelo menos uma letra minúscula";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "deve conter pelo menos um número";
    }
    
    // Verificar senhas comuns
    $commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123', 
        'password123', 'admin', 'root', 'user', 'test'
    ];
    
    if (in_array(strtolower($password), $commonPasswords)) {
        $errors[] = "não pode ser uma senha comum";
    }
    
    if (!empty($errors)) {
        return [
            'valid' => false,
            'error' => 'A senha ' . implode(', ', $errors) . '.'
        ];
    }
    
    return ['valid' => true];
}

/**
 * Verificar rate limiting
 */
function checkRateLimit($identifier, $action) {
    try {
        $pdo = getDB();
        
        $limits = [
            'login' => ['attempts' => 5, 'window' => 900], // 5 tentativas em 15 minutos
            'forgot_password' => ['attempts' => 3, 'window' => 3600] // 3 tentativas em 1 hora
        ];
        
        if (!isset($limits[$action])) {
            return true; // Ação não limitada
        }
        
        $limit = $limits[$action];
        
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as attempts 
            FROM rate_limits 
            WHERE identifier = ? AND action = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
        ");
        $stmt->execute([$identifier, $action, $limit['window']]);
        $result = $stmt->fetch();
        
        return $result['attempts'] < $limit['attempts'];
        
    } catch (Exception $e) {
        error_log("Erro no rate limiting: " . $e->getMessage());
        return true; // Em caso de erro, permitir a ação
    }
}

/**
 * Incrementar contador de rate limiting
 */
function incrementRateLimit($identifier, $action) {
    try {
        $pdo = getDB();
        
        $stmt = $pdo->prepare("
            INSERT INTO rate_limits (identifier, action, created_at) 
            VALUES (?, ?, NOW())
        ");
        $stmt->execute([$identifier, $action]);
        
    } catch (Exception $e) {
        error_log("Erro ao incrementar rate limit: " . $e->getMessage());
    }
}

/**
 * Gerar token seguro
 */
function generateSecureToken($length = 32) {
    return bin2hex(random_bytes($length));
}

/*
==============================================
 TABELAS ADICIONAIS NECESSÁRIAS:
==============================================

-- Tabela para tokens de recuperação de senha
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_expires (expires_at)
);

-- Tabela para rate limiting
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT PRIMARY KEY AUTO_INCREMENT,
    identifier VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_identifier_action_time (identifier, action, created_at)
);

-- Limpeza automática de tokens expirados (executar periodicamente)
DELETE FROM password_reset_tokens WHERE expires_at < NOW();
DELETE FROM rate_limits WHERE created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR);

==============================================
 EXEMPLOS DE USO:
==============================================

// Login
fetch('/login_api.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        action: 'login',
        username: 'admin',
        password: 'vitoria2025',
        remember_me: false
    })
});

// Verificar status
fetch('/login_api.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'check' })
});

// Logout
fetch('/login_api.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'logout' })
});

// Alterar senha
fetch('/login_api.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        action: 'change_password',
        current_password: 'senha_atual',
        new_password: 'Nova@Senha123'
    })
});

// Esqueci minha senha
fetch('/login_api.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        action: 'forgot_password',
        email: 'admin@condominiovitoriaregia.com'
    })
});

==============================================
*/
?>