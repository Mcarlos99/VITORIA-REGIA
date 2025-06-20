<?php
/**
 * Sistema de Segurança Centralizado - Condomínio Vitória Régia
 * 
 * Este arquivo centraliza todas as funções de segurança do sistema:
 * - Headers de segurança
 * - Proteção CSRF
 * - Rate limiting avançado
 * - Sanitização de dados
 * - Validações de entrada
 * - Logs de segurança
 * - Detecção de ataques
 * - Bloqueio de IPs suspeitos
 */

require_once 'config.php';

/**
 * Classe principal de segurança
 */
class SecurityManager {
    private $pdo;
    private $blockedIPs = [];
    private $suspiciousPatterns = [];
    
    public function __construct() {
        $this->pdo = getDB();
        $this->loadBlockedIPs();
        $this->initializeSuspiciousPatterns();
    }
    
    /**
     * Configurar todos os headers de segurança
     */
    public function setSecurityHeaders() {
        // Prevenir clickjacking
        header('X-Frame-Options: DENY');
        
        // Prevenir MIME type sniffing
        header('X-Content-Type-Options: nosniff');
        
        // Ativar proteção XSS
        header('X-XSS-Protection: 1; mode=block');
        
        // Política de referência
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Remover informações do servidor
        header_remove('X-Powered-By');
        header_remove('Server');
        
        // Content Security Policy restritiva
        $csp = $this->generateCSP();
        header("Content-Security-Policy: $csp");
        
        // HSTS para HTTPS
        if ($this->isHTTPS()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
        
        // Permissions Policy (Feature Policy)
        $permissions = [
            'geolocation=()' => 'geolocation=()',
            'microphone=()' => 'microphone=()',
            'camera=()' => 'camera=()',
            'payment=()' => 'payment=()',
            'usb=()' => 'usb=()',
            'magnetometer=()' => 'magnetometer=()',
            'gyroscope=()' => 'gyroscope=()',
            'accelerometer=()' => 'accelerometer=()'
        ];
        header('Permissions-Policy: ' . implode(', ', $permissions));
        
        // Cache control para páginas sensíveis
        if ($this->isSensitivePage()) {
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
        }
    }
    
    /**
     * Gerar Content Security Policy
     */
    private function generateCSP() {
        $nonce = $this->generateNonce();
        $_SESSION['csp_nonce'] = $nonce;
        
        $directives = [
            "default-src 'self'",
            "script-src 'self' 'nonce-$nonce'",
            "style-src 'self' 'unsafe-inline'", // Para Tailwind/CSS inline
            "img-src 'self' data: blob:",
            "font-src 'self'",
            "connect-src 'self'",
            "media-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests"
        ];
        
        return implode('; ', $directives);
    }
    
    /**
     * Verificar se a conexão é HTTPS
     */
    private function isHTTPS() {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               $_SERVER['SERVER_PORT'] == 443 ||
               (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    }
    
    /**
     * Verificar se é página sensível
     */
    private function isSensitivePage() {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $sensitivePages = ['/admin', '/login', '/api/', '/upload'];
        
        foreach ($sensitivePages as $page) {
            if (strpos($uri, $page) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Proteção CSRF
     */
    public function generateCSRFToken() {
        if (!isset($_SESSION['csrf_token']) || 
            !isset($_SESSION['csrf_token_time']) || 
            (time() - $_SESSION['csrf_token_time']) > CSRF_TOKEN_EXPIRE) {
            
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        return $_SESSION['csrf_token'];
    }
    
    /**
     * Validar token CSRF
     */
    public function validateCSRFToken($token) {
        if (!isset($_SESSION['csrf_token']) || 
            !isset($_SESSION['csrf_token_time'])) {
            return false;
        }
        
        // Verificar expiração
        if ((time() - $_SESSION['csrf_token_time']) > CSRF_TOKEN_EXPIRE) {
            unset($_SESSION['csrf_token']);
            unset($_SESSION['csrf_token_time']);
            return false;
        }
        
        return hash_equals($_SESSION['csrf_token'], $token);
    }
    
    /**
     * Rate limiting avançado
     */
    public function checkRateLimit($identifier, $action, $maxAttempts = null, $timeWindow = null) {
        $limits = $this->getRateLimits();
        
        if (!isset($limits[$action])) {
            return true; // Ação não limitada
        }
        
        $limit = $limits[$action];
        $maxAttempts = $maxAttempts ?? $limit['max_attempts'];
        $timeWindow = $timeWindow ?? $limit['time_window'];
        
        try {
            // Verificar tentativas atuais
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) as attempts 
                FROM rate_limits 
                WHERE identifier = ? AND action = ? 
                AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
            ");
            $stmt->execute([$identifier, $action, $timeWindow]);
            $result = $stmt->fetch();
            
            $currentAttempts = $result['attempts'];
            
            // Verificar se excedeu o limite
            if ($currentAttempts >= $maxAttempts) {
                $this->logSecurityEvent('rate_limit_exceeded', $identifier, [
                    'action' => $action,
                    'attempts' => $currentAttempts,
                    'limit' => $maxAttempts
                ]);
                
                // Bloquear IP se muitas violações
                if ($currentAttempts >= ($maxAttempts * 3)) {
                    $this->blockIP($identifier, 'rate_limit_violation');
                }
                
                return false;
            }
            
            return true;
            
        } catch (Exception $e) {
            error_log("Erro no rate limiting: " . $e->getMessage());
            return true; // Em caso de erro, permitir acesso
        }
    }
    
    /**
     * Incrementar contador de rate limiting
     */
    public function incrementRateLimit($identifier, $action) {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO rate_limits (identifier, action, created_at) 
                VALUES (?, ?, NOW())
            ");
            $stmt->execute([$identifier, $action]);
        } catch (Exception $e) {
            error_log("Erro ao incrementar rate limit: " . $e->getMessage());
        }
    }
    
    /**
     * Obter configurações de rate limiting
     */
    private function getRateLimits() {
        return [
            'login' => ['max_attempts' => 5, 'time_window' => 900], // 5 tentativas em 15 min
            'api_request' => ['max_attempts' => 100, 'time_window' => 60], // 100 req/min
            'upload' => ['max_attempts' => 10, 'time_window' => 300], // 10 uploads em 5 min
            'password_reset' => ['max_attempts' => 3, 'time_window' => 3600], // 3 tentativas/hora
            'contact_form' => ['max_attempts' => 5, 'time_window' => 3600], // 5 envios/hora
        ];
    }
    
    /**
     * Sanitização avançada de dados
     */
    public function sanitizeInput($input, $type = 'string') {
        if (is_array($input)) {
            return array_map(function($item) use ($type) {
                return $this->sanitizeInput($item, $type);
            }, $input);
        }
        
        // Remover null bytes
        $input = str_replace("\0", '', $input);
        
        switch ($type) {
            case 'email':
                return filter_var($input, FILTER_SANITIZE_EMAIL);
                
            case 'url':
                return filter_var($input, FILTER_SANITIZE_URL);
                
            case 'int':
                return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
                
            case 'float':
                return filter_var($input, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
                
            case 'html':
                return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                
            case 'sql':
                // Para uso com prepared statements
                return trim($input);
                
            case 'filename':
                // Sanitizar nome de arquivo
                $input = basename($input);
                $input = preg_replace('/[^a-zA-Z0-9._-]/', '_', $input);
                return substr($input, 0, 255);
                
            case 'alphanumeric':
                return preg_replace('/[^a-zA-Z0-9]/', '', $input);
                
            case 'phone':
                return preg_replace('/[^0-9+()-\s]/', '', $input);
                
            case 'string':
            default:
                return htmlspecialchars(trim($input), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
    }
    
    /**
     * Validações de entrada
     */
    public function validateInput($input, $rules) {
        $errors = [];
        
        foreach ($rules as $field => $fieldRules) {
            $value = $input[$field] ?? null;
            
            foreach ($fieldRules as $rule => $ruleValue) {
                switch ($rule) {
                    case 'required':
                        if ($ruleValue && (is_null($value) || trim($value) === '')) {
                            $errors[$field][] = "Campo $field é obrigatório";
                        }
                        break;
                        
                    case 'min_length':
                        if (!is_null($value) && strlen($value) < $ruleValue) {
                            $errors[$field][] = "Campo $field deve ter pelo menos $ruleValue caracteres";
                        }
                        break;
                        
                    case 'max_length':
                        if (!is_null($value) && strlen($value) > $ruleValue) {
                            $errors[$field][] = "Campo $field deve ter no máximo $ruleValue caracteres";
                        }
                        break;
                        
                    case 'email':
                        if (!is_null($value) && $ruleValue && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                            $errors[$field][] = "Campo $field deve ser um email válido";
                        }
                        break;
                        
                    case 'numeric':
                        if (!is_null($value) && $ruleValue && !is_numeric($value)) {
                            $errors[$field][] = "Campo $field deve ser numérico";
                        }
                        break;
                        
                    case 'integer':
                        if (!is_null($value) && $ruleValue && !filter_var($value, FILTER_VALIDATE_INT)) {
                            $errors[$field][] = "Campo $field deve ser um número inteiro";
                        }
                        break;
                        
                    case 'min_value':
                        if (!is_null($value) && is_numeric($value) && floatval($value) < $ruleValue) {
                            $errors[$field][] = "Campo $field deve ser pelo menos $ruleValue";
                        }
                        break;
                        
                    case 'max_value':
                        if (!is_null($value) && is_numeric($value) && floatval($value) > $ruleValue) {
                            $errors[$field][] = "Campo $field deve ser no máximo $ruleValue";
                        }
                        break;
                        
                    case 'regex':
                        if (!is_null($value) && !preg_match($ruleValue, $value)) {
                            $errors[$field][] = "Campo $field tem formato inválido";
                        }
                        break;
                        
                    case 'in':
                        if (!is_null($value) && !in_array($value, $ruleValue)) {
                            $errors[$field][] = "Campo $field tem valor inválido";
                        }
                        break;
                        
                    case 'date':
                        if (!is_null($value) && $ruleValue) {
                            $date = DateTime::createFromFormat('Y-m-d', $value);
                            if (!$date || $date->format('Y-m-d') !== $value) {
                                $errors[$field][] = "Campo $field deve ser uma data válida (YYYY-MM-DD)";
                            }
                        }
                        break;
                }
            }
        }
        
        return $errors;
    }
    
    /**
     * Detectar padrões suspeitos
     */
    public function detectSuspiciousActivity($input) {
        $suspicious = [];
        
        foreach ($this->suspiciousPatterns as $pattern => $description) {
            if (preg_match($pattern, $input)) {
                $suspicious[] = $description;
            }
        }
        
        // Verificar tentativas de path traversal
        if (strpos($input, '../') !== false || strpos($input, '..\\') !== false) {
            $suspicious[] = 'path_traversal_attempt';
        }
        
        // Verificar tentativas de injeção SQL
        $sqlPatterns = ['/union\s+select/i', '/drop\s+table/i', '/insert\s+into/i', '/update\s+set/i'];
        foreach ($sqlPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                $suspicious[] = 'sql_injection_attempt';
                break;
            }
        }
        
        // Verificar tentativas de XSS
        if (preg_match('/<script|javascript:|on\w+\s*=/i', $input)) {
            $suspicious[] = 'xss_attempt';
        }
        
        return $suspicious;
    }
    
    /**
     * Inicializar padrões suspeitos
     */
    private function initializeSuspiciousPatterns() {
        $this->suspiciousPatterns = [
            // Injeção de comandos
            '/;\s*(rm|del|format|cat|type|more|less|head|tail|grep|find|ls|dir)/i' => 'command_injection',
            
            // Tentativas de inclusão de arquivo
            '/(include|require|file_get_contents|fopen|readfile)\s*\(/i' => 'file_inclusion',
            
            // Tentativas de execução de código
            '/(eval|exec|system|shell_exec|passthru|proc_open)\s*\(/i' => 'code_execution',
            
            // User agents suspeitos
            '/(sqlmap|nikto|nmap|masscan|zap|burp|crawler|bot)/i' => 'suspicious_user_agent',
            
            // Tentativas de scan
            '/\.(php|asp|jsp|cgi|pl)(\?|$)/i' => 'file_scan_attempt',
        ];
    }
    
    /**
     * Bloquear IP
     */
    public function blockIP($ip, $reason, $duration = 3600) {
        try {
            $expiresAt = date('Y-m-d H:i:s', time() + $duration);
            
            $stmt = $this->pdo->prepare("
                INSERT INTO blocked_ips (ip_address, reason, expires_at, created_at)
                VALUES (?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE 
                    reason = VALUES(reason),
                    expires_at = VALUES(expires_at),
                    block_count = block_count + 1
            ");
            $stmt->execute([$ip, $reason, $expiresAt]);
            
            $this->logSecurityEvent('ip_blocked', $ip, [
                'reason' => $reason,
                'duration' => $duration,
                'expires_at' => $expiresAt
            ]);
            
            // Recarregar lista de IPs bloqueados
            $this->loadBlockedIPs();
            
        } catch (Exception $e) {
            error_log("Erro ao bloquear IP: " . $e->getMessage());
        }
    }
    
    /**
     * Verificar se IP está bloqueado
     */
    public function isIPBlocked($ip) {
        return in_array($ip, $this->blockedIPs);
    }
    
    /**
     * Carregar IPs bloqueados
     */
    private function loadBlockedIPs() {
        try {
            $stmt = $this->pdo->query("
                SELECT ip_address 
                FROM blocked_ips 
                WHERE expires_at > NOW()
            ");
            $this->blockedIPs = $stmt->fetchAll(PDO::FETCH_COLUMN);
        } catch (Exception $e) {
            error_log("Erro ao carregar IPs bloqueados: " . $e->getMessage());
            $this->blockedIPs = [];
        }
    }
    
    /**
     * Log de eventos de segurança
     */
    public function logSecurityEvent($event, $identifier, $details = []) {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO security_events (
                    event_type, identifier, ip_address, user_agent, 
                    details, severity, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, NOW())
            ");
            
            $severity = $this->getEventSeverity($event);
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            $detailsJson = json_encode($details);
            
            $stmt->execute([
                $event,
                $identifier,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $userAgent,
                $detailsJson,
                $severity
            ]);
            
            // Log crítico também no arquivo
            if ($severity === 'critical') {
                error_log("SECURITY CRITICAL: $event - $identifier - " . json_encode($details));
            }
            
        } catch (Exception $e) {
            error_log("Erro ao registrar evento de segurança: " . $e->getMessage());
        }
    }
    
    /**
     * Determinar severidade do evento
     */
    private function getEventSeverity($event) {
        $criticalEvents = [
            'sql_injection_attempt', 'xss_attempt', 'command_injection',
            'file_inclusion', 'code_execution', 'multiple_login_failures'
        ];
        
        $warningEvents = [
            'rate_limit_exceeded', 'suspicious_user_agent', 'path_traversal_attempt'
        ];
        
        if (in_array($event, $criticalEvents)) {
            return 'critical';
        } elseif (in_array($event, $warningEvents)) {
            return 'warning';
        } else {
            return 'info';
        }
    }
    
    /**
     * Gerar nonce para CSP
     */
    private function generateNonce() {
        return base64_encode(random_bytes(16));
    }
    
    /**
     * Middleware de segurança para requisições
     */
    public function securityMiddleware() {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Verificar IP bloqueado
        if ($this->isIPBlocked($ip)) {
            http_response_code(403);
            die('Access denied. Your IP is temporarily blocked.');
        }
        
        // Verificar rate limiting geral
        if (!$this->checkRateLimit($ip, 'general_request', 200, 60)) {
            http_response_code(429);
            die('Too many requests. Please slow down.');
        }
        
        // Detectar atividade suspeita na URI
        $suspicious = $this->detectSuspiciousActivity($uri);
        if (!empty($suspicious)) {
            $this->logSecurityEvent('suspicious_request', $ip, [
                'uri' => $uri,
                'patterns' => $suspicious,
                'user_agent' => $userAgent
            ]);
            
            // Bloquear se muito suspeito
            $criticalPatterns = ['sql_injection_attempt', 'xss_attempt', 'command_injection'];
            if (array_intersect($suspicious, $criticalPatterns)) {
                $this->blockIP($ip, 'malicious_request');
                http_response_code(403);
                die('Malicious request detected.');
            }
        }
        
        // Incrementar contador geral
        $this->incrementRateLimit($ip, 'general_request');
    }
    
    /**
     * Limpeza de dados antigos
     */
    public function cleanup() {
        try {
            // Limpar rate limits antigos (> 24h)
            $this->pdo->query("
                DELETE FROM rate_limits 
                WHERE created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)
            ");
            
            // Limpar IPs bloqueados expirados
            $this->pdo->query("
                DELETE FROM blocked_ips 
                WHERE expires_at < NOW()
            ");
            
            // Limpar eventos de segurança antigos (> 30 dias)
            $this->pdo->query("
                DELETE FROM security_events 
                WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
                AND severity != 'critical'
            ");
            
            // Recarregar IPs bloqueados
            $this->loadBlockedIPs();
            
        } catch (Exception $e) {
            error_log("Erro na limpeza de segurança: " . $e->getMessage());
        }
    }
}

// Funções helper globais
function getSecurity() {
    static $security = null;
    if ($security === null) {
        $security = new SecurityManager();
    }
    return $security;
}

function sanitize($input, $type = 'string') {
    return getSecurity()->sanitizeInput($input, $type);
}

function validateData($data, $rules) {
    return getSecurity()->validateInput($data, $rules);
}

function checkRateLimit($identifier, $action, $maxAttempts = null, $timeWindow = null) {
    return getSecurity()->checkRateLimit($identifier, $action, $maxAttempts, $timeWindow);
}

function logSecurityEvent($event, $identifier, $details = []) {
    getSecurity()->logSecurityEvent($event, $identifier, $details);
}

/*
==============================================
 TABELAS NECESSÁRIAS PARA SEGURANÇA:
==============================================

-- IPs bloqueados
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(100) NOT NULL,
    block_count INT DEFAULT 1,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_expires (ip_address, expires_at)
);

-- Eventos de segurança
CREATE TABLE IF NOT EXISTS security_events (
    id INT PRIMARY KEY AUTO_INCREMENT,
    event_type VARCHAR(50) NOT NULL,
    identifier VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    severity ENUM('info', 'warning', 'critical') DEFAULT 'info',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_time (event_type, created_at),
    INDEX idx_severity_time (severity, created_at),
    INDEX idx_ip_time (ip_address, created_at)
);

-- Rate limiting (já existe, mas com índices otimizados)
ALTER TABLE rate_limits 
ADD INDEX idx_identifier_action_time (identifier, action, created_at);

==============================================
 EXEMPLO DE USO:
==============================================

// No início de cada script importante
require_once 'security.php';

$security = getSecurity();
$security->setSecurityHeaders();
$security->securityMiddleware();

// Sanitização de dados
$nome = sanitize($_POST['nome'], 'string');
$email = sanitize($_POST['email'], 'email');
$telefone = sanitize($_POST['telefone'], 'phone');

// Validação
$errors = validateData($_POST, [
    'nome' => ['required' => true, 'min_length' => 2, 'max_length' => 100],
    'email' => ['required' => true, 'email' => true],
    'idade' => ['numeric' => true, 'min_value' => 0, 'max_value' => 150]
]);

// Rate limiting específico
if (!checkRateLimit($userIP, 'contact_form', 5, 3600)) {
    die('Muitas tentativas. Tente em 1 hora.');
}

// CSRF protection
$token = $security->generateCSRFToken();
if ($_POST && !$security->validateCSRFToken($_POST['csrf_token'])) {
    die('Token CSRF inválido');
}

==============================================
*/
?>