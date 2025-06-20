<?php
/**
 * Sistema de Autenticação - Condomínio Vitória Régia
 * 
 * Este arquivo gerencia:
 * - Login e logout de usuários
 * - Controle de sessões
 * - Validação de permissões
 * - Proteção contra ataques de força bruta
 * - Logs de segurança
 */

require_once 'config.php';

// Iniciar sessão se ainda não foi iniciada
if (session_status() == PHP_SESSION_NONE) {
    // Configurações de segurança da sessão
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? 1 : 0);
    ini_set('session.cookie_samesite', 'Strict');
    
    session_start();
}

/**
 * Classe principal de autenticação
 */
class Auth {
    private $pdo;
    
    public function __construct() {
        $this->pdo = getDB();
        $this->cleanupExpiredSessions();
    }
    
    /**
     * Realizar login do usuário
     */
    public function login($username, $password, $rememberMe = false) {
        try {
            // Verificar tentativas de login
            if (!$this->checkLoginAttempts($username, $_SERVER['REMOTE_ADDR'])) {
                $this->logSecurity("Login bloqueado por muitas tentativas", $username, $_SERVER['REMOTE_ADDR']);
                return [
                    'success' => false, 
                    'message' => 'Muitas tentativas de login. Tente novamente em ' . (LOGIN_LOCKOUT_TIME / 60) . ' minutos.'
                ];
            }
            
            // Buscar usuário no banco
            $stmt = $this->pdo->prepare("SELECT * FROM usuarios WHERE username = ? AND ativo = 1");
            $stmt->execute([$username]);
            $usuario = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($usuario && password_verify($password, $usuario['password_hash'])) {
                // Login bem-sucedido
                $this->createUserSession($usuario, $rememberMe);
                $this->updateLastLogin($usuario['id']);
                $this->logLoginAttempt($username, $_SERVER['REMOTE_ADDR'], true);
                $this->logSecurity("Login bem-sucedido", $username, $_SERVER['REMOTE_ADDR']);
                
                return [
                    'success' => true,
                    'message' => 'Login realizado com sucesso!',
                    'user' => [
                        'id' => $usuario['id'],
                        'username' => $usuario['username'],
                        'nome' => $usuario['nome'],
                        'email' => $usuario['email']
                    ]
                ];
            } else {
                // Login falhou
                $this->logLoginAttempt($username, $_SERVER['REMOTE_ADDR'], false);
                $this->logSecurity("Tentativa de login falhada", $username, $_SERVER['REMOTE_ADDR']);
                
                return [
                    'success' => false,
                    'message' => 'Usuário ou senha incorretos.'
                ];
            }
            
        } catch (Exception $e) {
            error_log("Erro no login: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Erro interno do sistema. Tente novamente.'
            ];
        }
    }
    
    /**
     * Criar sessão do usuário
     */
    private function createUserSession($usuario, $rememberMe = false) {
        // Regenerar ID da sessão para segurança
        session_regenerate_id(true);
        
        // Definir dados da sessão
        $_SESSION['user_id'] = $usuario['id'];
        $_SESSION['username'] = $usuario['username'];
        $_SESSION['nome'] = $usuario['nome'];
        $_SESSION['email'] = $usuario['email'];
        $_SESSION['login_time'] = time();
        $_SESSION['last_activity'] = time();
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        
        // Calcular tempo de expiração
        $expiresAt = date('Y-m-d H:i:s', time() + SESSION_TIMEOUT);
        if ($rememberMe) {
            $expiresAt = date('Y-m-d H:i:s', time() + (30 * 24 * 60 * 60)); // 30 dias
        }
        
        // Salvar sessão no banco de dados
        $stmt = $this->pdo->prepare("
            INSERT INTO sessoes (id, usuario_id, ip_address, user_agent, expires_at) 
            VALUES (?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE 
                expires_at = VALUES(expires_at),
                ip_address = VALUES(ip_address),
                user_agent = VALUES(user_agent)
        ");
        
        $stmt->execute([
            session_id(),
            $usuario['id'],
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT'],
            $expiresAt
        ]);
        
        // Configurar cookie se "lembrar de mim" estiver marcado
        if ($rememberMe) {
            setcookie(session_name(), session_id(), time() + (30 * 24 * 60 * 60), '/', '', isset($_SERVER['HTTPS']), true);
        }
    }
    
    /**
     * Verificar se usuário está logado
     */
    public function isLoggedIn() {
        // Verificar se existe sessão
        if (!isset($_SESSION['user_id'])) {
            return false;
        }
        
        // Verificar timeout de inatividade
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
            $this->logout();
            return false;
        }
        
        // Verificar se IP mudou (proteção contra sequestro de sessão)
        if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
            $this->logSecurity("IP da sessão alterado", $_SESSION['username'], $_SERVER['REMOTE_ADDR']);
            $this->logout();
            return false;
        }
        
        // Verificar sessão no banco de dados
        $stmt = $this->pdo->prepare("
            SELECT u.ativo 
            FROM sessoes s 
            JOIN usuarios u ON s.usuario_id = u.id 
            WHERE s.id = ? AND s.usuario_id = ? AND s.expires_at > NOW() AND u.ativo = 1
        ");
        $stmt->execute([session_id(), $_SESSION['user_id']]);
        
        if (!$stmt->fetch()) {
            $this->logout();
            return false;
        }
        
        // Atualizar última atividade
        $_SESSION['last_activity'] = time();
        
        return true;
    }
    
    /**
     * Fazer logout
     */
    public function logout() {
        try {
            // Remover sessão do banco de dados
            if (isset($_SESSION['user_id'])) {
                $stmt = $this->pdo->prepare("DELETE FROM sessoes WHERE id = ?");
                $stmt->execute([session_id()]);
                
                $this->logSecurity("Logout realizado", $_SESSION['username'] ?? 'unknown', $_SERVER['REMOTE_ADDR']);
            }
            
            // Limpar variáveis de sessão
            $_SESSION = array();
            
            // Remover cookie de sessão
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
            
            // Destruir sessão
            session_destroy();
            
            return ['success' => true, 'message' => 'Logout realizado com sucesso.'];
            
        } catch (Exception $e) {
            error_log("Erro no logout: " . $e->getMessage());
            return ['success' => false, 'message' => 'Erro ao fazer logout.'];
        }
    }
    
    /**
     * Verificar tentativas de login
     */
    private function checkLoginAttempts($username, $ipAddress) {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as attempts 
            FROM login_attempts 
            WHERE (username = ? OR ip_address = ?) 
            AND success = 0 
            AND attempt_time > DATE_SUB(NOW(), INTERVAL ? MINUTE)
        ");
        
        $stmt->execute([$username, $ipAddress, LOGIN_LOCKOUT_TIME / 60]);
        $result = $stmt->fetch();
        
        return $result['attempts'] < MAX_LOGIN_ATTEMPTS;
    }
    
    /**
     * Registrar tentativa de login
     */
    private function logLoginAttempt($username, $ipAddress, $success) {
        $stmt = $this->pdo->prepare("
            INSERT INTO login_attempts (username, ip_address, success, attempt_time) 
            VALUES (?, ?, ?, NOW())
        ");
        $stmt->execute([$username, $ipAddress, $success ? 1 : 0]);
    }
    
    /**
     * Atualizar último login
     */
    private function updateLastLogin($userId) {
        $stmt = $this->pdo->prepare("UPDATE usuarios SET ultimo_login = NOW() WHERE id = ?");
        $stmt->execute([$userId]);
    }
    
    /**
     * Limpar sessões expiradas
     */
    private function cleanupExpiredSessions() {
        try {
            $stmt = $this->pdo->prepare("DELETE FROM sessoes WHERE expires_at < NOW()");
            $stmt->execute();
            
            // Limpar tentativas de login antigas
            $stmt = $this->pdo->prepare("DELETE FROM login_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $stmt->execute();
            
        } catch (Exception $e) {
            error_log("Erro ao limpar sessões: " . $e->getMessage());
        }
    }
    
    /**
     * Obter informações do usuário logado
     */
    public function getUserInfo() {
        if (!$this->isLoggedIn()) {
            return null;
        }
        
        return [
            'id' => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
            'nome' => $_SESSION['nome'],
            'email' => $_SESSION['email'],
            'login_time' => $_SESSION['login_time'],
            'last_activity' => $_SESSION['last_activity']
        ];
    }
    
    /**
     * Verificar se usuário tem permissão específica
     */
    public function hasPermission($permission) {
        // Por enquanto, todos os usuários logados têm todas as permissões
        // Esta função pode ser expandida para um sistema de roles mais complexo
        return $this->isLoggedIn();
    }
    
    /**
     * Alterar senha do usuário
     */
    public function changePassword($currentPassword, $newPassword) {
        if (!$this->isLoggedIn()) {
            return ['success' => false, 'message' => 'Usuário não está logado.'];
        }
        
        try {
            // Verificar senha atual
            $stmt = $this->pdo->prepare("SELECT password_hash FROM usuarios WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $user = $stmt->fetch();
            
            if (!password_verify($currentPassword, $user['password_hash'])) {
                return ['success' => false, 'message' => 'Senha atual incorreta.'];
            }
            
            // Validar nova senha
            if (strlen($newPassword) < 6) {
                return ['success' => false, 'message' => 'Nova senha deve ter pelo menos 6 caracteres.'];
            }
            
            // Atualizar senha
            $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
            $stmt = $this->pdo->prepare("UPDATE usuarios SET password_hash = ? WHERE id = ?");
            $stmt->execute([$newHash, $_SESSION['user_id']]);
            
            $this->logSecurity("Senha alterada", $_SESSION['username'], $_SERVER['REMOTE_ADDR']);
            
            return ['success' => true, 'message' => 'Senha alterada com sucesso.'];
            
        } catch (Exception $e) {
            error_log("Erro ao alterar senha: " . $e->getMessage());
            return ['success' => false, 'message' => 'Erro interno. Tente novamente.'];
        }
    }
    
    /**
     * Log de eventos de segurança
     */
    private function logSecurity($event, $username, $ipAddress, $details = '') {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO security_logs (event, username, ip_address, details, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            $stmt->execute([$event, $username, $ipAddress, $details]);
            
            // Log também no arquivo
            logActivity("SECURITY: $event - User: $username, IP: $ipAddress", 'SECURITY', ['details' => $details]);
            
        } catch (Exception $e) {
            error_log("Erro ao registrar log de segurança: " . $e->getMessage());
        }
    }
    
    /**
     * Obter estatísticas de login
     */
    public function getLoginStats() {
        if (!$this->isLoggedIn()) {
            return null;
        }
        
        try {
            // Sessões ativas
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as active_sessions FROM sessoes WHERE expires_at > NOW()");
            $stmt->execute();
            $activeSessions = $stmt->fetch()['active_sessions'];
            
            // Tentativas de login hoje
            $stmt = $this->pdo->prepare("
                SELECT 
                    COUNT(*) as total_attempts,
                    SUM(success) as successful_attempts,
                    COUNT(*) - SUM(success) as failed_attempts
                FROM login_attempts 
                WHERE DATE(attempt_time) = CURDATE()
            ");
            $stmt->execute();
            $todayStats = $stmt->fetch();
            
            return [
                'active_sessions' => $activeSessions,
                'today_total_attempts' => $todayStats['total_attempts'],
                'today_successful' => $todayStats['successful_attempts'],
                'today_failed' => $todayStats['failed_attempts']
            ];
            
        } catch (Exception $e) {
            error_log("Erro ao obter estatísticas: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Forçar logout de todas as sessões do usuário
     */
    public function logoutAllSessions() {
        if (!$this->isLoggedIn()) {
            return false;
        }
        
        try {
            $stmt = $this->pdo->prepare("DELETE FROM sessoes WHERE usuario_id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            
            $this->logSecurity("Logout de todas as sessões", $_SESSION['username'], $_SERVER['REMOTE_ADDR']);
            
            // Fazer logout da sessão atual
            $this->logout();
            
            return true;
            
        } catch (Exception $e) {
            error_log("Erro ao fazer logout de todas as sessões: " . $e->getMessage());
            return false;
        }
    }
}

/**
 * Função helper para verificar autenticação
 */
function requireAuth() {
    $auth = new Auth();
    if (!$auth->isLoggedIn()) {
        // Se é uma requisição AJAX, retornar JSON
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            http_response_code(401);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Não autorizado. Faça login novamente.']);
            exit;
        }
        
        // Se é requisição normal, redirecionar para login
        header('Location: login.php');
        exit;
    }
    
    return $auth;
}

/**
 * Função helper para obter usuário atual
 */
function getCurrentUser() {
    $auth = new Auth();
    return $auth->getUserInfo();
}

/**
 * Função helper para verificar permissão
 */
function hasPermission($permission) {
    $auth = new Auth();
    return $auth->hasPermission($permission);
}

/**
 * Middleware de autenticação para APIs
 */
function authMiddleware() {
    $auth = new Auth();
    if (!$auth->isLoggedIn()) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'error' => 'Acesso negado. Faça login para continuar.'
        ]);
        exit;
    }
    return $auth;
}

/*
==============================================
 TABELAS NECESSÁRIAS NO BANCO DE DADOS:
==============================================

-- Tabela de usuários (já criada em config.php)

-- Tabela de sessões
CREATE TABLE IF NOT EXISTS sessoes (
    id VARCHAR(128) PRIMARY KEY,
    usuario_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_expires (expires_at),
    INDEX idx_usuario (usuario_id)
);

-- Tabela de tentativas de login
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    ip_address VARCHAR(45),
    success BOOLEAN DEFAULT FALSE,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username_time (username, attempt_time),
    INDEX idx_ip_time (ip_address, attempt_time)
);

-- Tabela de logs de segurança
CREATE TABLE IF NOT EXISTS security_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    event VARCHAR(100) NOT NULL,
    username VARCHAR(50),
    ip_address VARCHAR(45),
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_time (event, created_at),
    INDEX idx_username_time (username, created_at)
);

==============================================
*/
?>