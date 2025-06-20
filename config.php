<?php
/**
 * Arquivo de Configuração - Condomínio Vitória Régia
 * Sistema de Gerenciamento de Condomínio
 * 
 * Este arquivo contém as configurações principais do sistema:
 * - Conexão com banco de dados
 * - Configurações de upload
 * - Configurações de segurança
 * - Constantes do sistema
 */

// Configurações do Banco de Dados
define('DB_HOST', 'localhost');           // Servidor do banco (geralmente localhost)
define('DB_NAME', 'extremes_cond_vitoria_regia'); // Nome do banco de dados
define('DB_USER', 'extremes_condvitoriaregia');         // Usuário do MySQL - ALTERE AQUI
define('DB_PASS', '(,;JmYvZjB0cEL0R');           // Senha do MySQL - ALTERE AQUI
define('DB_CHARSET', 'utf8mb4');          // Charset do banco

// Configurações de Upload
define('UPLOAD_MAX_SIZE', 5 * 1024 * 1024);  // 5MB em bytes
define('UPLOAD_DIR_CONTRATOS', 'uploads/contratos/');
define('UPLOAD_DIR_COMPROVANTES', 'uploads/comprovantes/');
define('ALLOWED_FILE_TYPES', ['jpg', 'jpeg', 'png', 'pdf']);

// Configurações de Segurança
define('SESSION_TIMEOUT', 2 * 60 * 60);   // 2 horas em segundos
define('MAX_LOGIN_ATTEMPTS', 5);          // Máximo de tentativas de login
define('LOGIN_LOCKOUT_TIME', 15 * 60);    // 15 minutos em segundos
define('CSRF_TOKEN_EXPIRE', 60 * 60);     // 1 hora em segundos

// Configurações do Sistema
define('SYSTEM_NAME', 'Condomínio Vitória Régia');
define('SYSTEM_VERSION', '1.0.0');
define('TIMEZONE', 'America/Sao_Paulo');
define('DATE_FORMAT', 'd/m/Y');
define('DATETIME_FORMAT', 'd/m/Y H:i:s');

// Configurações de Desenvolvimento
define('DEBUG_MODE', false);              // Altere para true apenas em desenvolvimento
define('LOG_ERRORS', true);
define('ERROR_LOG_FILE', 'logs/error.log');

// Definir timezone
date_default_timezone_set(TIMEZONE);

// Configurar exibição de erros baseado no modo debug
if (DEBUG_MODE) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
} else {
    error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED);
    ini_set('display_errors', 0);
    ini_set('display_startup_errors', 0);
}

// Configurar log de erros
if (LOG_ERRORS) {
    ini_set('log_errors', 1);
    ini_set('error_log', ERROR_LOG_FILE);
}

/**
 * Classe de Conexão com Banco de Dados
 */
class Database {
    private static $instance = null;
    private $pdo;
    
    private function __construct() {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
            
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::ATTR_PERSISTENT         => true,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET . " COLLATE utf8mb4_unicode_ci"
            ];
            
            $this->pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
            
            // Log de conexão bem-sucedida (apenas em debug)
            if (DEBUG_MODE) {
                error_log("Conexão com banco de dados estabelecida com sucesso");
            }
            
        } catch (PDOException $e) {
            // Log do erro
            error_log("Erro na conexão com banco de dados: " . $e->getMessage());
            
            // Em produção, não mostrar detalhes do erro
            if (DEBUG_MODE) {
                die("Erro na conexão com banco de dados: " . $e->getMessage());
            } else {
                die("Erro interno do sistema. Tente novamente mais tarde.");
            }
        }
    }
    
    /**
     * Singleton - Retorna uma única instância da conexão
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Retorna a conexão PDO
     */
    public function getConnection() {
        return $this->pdo;
    }
    
    /**
     * Previne clonagem da instância
     */
    private function __clone() {}
    
    /**
     * Previne desserialização da instância
     */
    public function __wakeup() {
        throw new Exception("Cannot unserialize singleton");
    }
}

/**
 * Função helper para obter conexão com banco
 */
function getDB() {
    return Database::getInstance()->getConnection();
}

/**
 * Função para criar diretórios necessários
 */
function createRequiredDirectories() {
    $directories = [
        UPLOAD_DIR_CONTRATOS,
        UPLOAD_DIR_COMPROVANTES,
        'logs/'
    ];
    
    foreach ($directories as $dir) {
        if (!is_dir($dir)) {
            if (mkdir($dir, 0755, true)) {
                if (DEBUG_MODE) {
                    error_log("Diretório criado: $dir");
                }
                
                // Criar arquivo .htaccess para proteção
                if (strpos($dir, 'uploads/') === 0) {
                    createUploadProtection($dir);
                }
            } else {
                error_log("Erro ao criar diretório: $dir");
            }
        }
    }
}

/**
 * Função para criar proteção nos diretórios de upload
 */
function createUploadProtection($dir) {
    $htaccessContent = "
# Proteção de segurança para uploads
php_flag engine off
AddHandler cgi-script .php .phtml .php3 .pl .py .jsp .asp .sh .cgi
Options -ExecCGI -Indexes

# Permitir apenas tipos específicos
<Files ~ \"\.(jpg|jpeg|png|pdf)$\">
    Order allow,deny
    Allow from all
</Files>

# Bloquear todo o resto
<Files ~ \"\.\">
    Order allow,deny
    Deny from all
</Files>
";
    
    file_put_contents($dir . '.htaccess', $htaccessContent);
}

/**
 * Função para validar configurações
 */
function validateConfiguration() {
    $errors = [];
    
    // Verificar se extensões necessárias estão instaladas
    if (!extension_loaded('pdo')) {
        $errors[] = "Extensão PDO não encontrada";
    }
    
    if (!extension_loaded('pdo_mysql')) {
        $errors[] = "Extensão PDO MySQL não encontrada";
    }
    
    if (!extension_loaded('gd')) {
        $errors[] = "Extensão GD não encontrada (necessária para processamento de imagens)";
    }
    
    // Verificar permissões de escrita
    if (!is_writable('uploads/')) {
        $errors[] = "Pasta uploads/ não tem permissão de escrita";
    }
    
    if (!is_writable('logs/')) {
        $errors[] = "Pasta logs/ não tem permissão de escrita";
    }
    
    // Verificar configurações PHP importantes
    if (ini_get('file_uploads') != 1) {
        $errors[] = "Upload de arquivos está desabilitado no PHP";
    }
    
    $maxFileSize = ini_get('upload_max_filesize');
    $maxPostSize = ini_get('post_max_size');
    
    if (DEBUG_MODE && !empty($errors)) {
        foreach ($errors as $error) {
            error_log("Erro de configuração: $error");
        }
    }
    
    return $errors;
}

/**
 * Função para log de atividades do sistema
 */
function logActivity($message, $level = 'INFO', $context = []) {
    $timestamp = date(DATETIME_FORMAT);
    $contextStr = !empty($context) ? json_encode($context) : '';
    $logMessage = "[$timestamp] [$level] $message $contextStr" . PHP_EOL;
    
    file_put_contents('logs/activity.log', $logMessage, FILE_APPEND | LOCK_EX);
}

/**
 * Função para formatação de bytes
 */
function formatBytes($size, $precision = 2) {
    if ($size == 0) return '0 B';
    
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $pow = floor(log($size) / log(1024));
    
    return round($size / pow(1024, $pow), $precision) . ' ' . $units[$pow];
}

/**
 * Inicialização automática
 */
try {
    // Criar diretórios necessários
    createRequiredDirectories();
    
    // Validar configurações
    $configErrors = validateConfiguration();
    
    if (!empty($configErrors) && DEBUG_MODE) {
        error_log("Avisos de configuração encontrados: " . implode(', ', $configErrors));
    }
    
    // Testar conexão com banco (apenas criar instância)
    Database::getInstance();
    
    if (DEBUG_MODE) {
        error_log("Sistema inicializado com sucesso");
    }
    
} catch (Exception $e) {
    error_log("Erro na inicialização do sistema: " . $e->getMessage());
    
    if (DEBUG_MODE) {
        die("Erro na inicialização: " . $e->getMessage());
    } else {
        die("Erro interno do sistema. Verifique as configurações.");
    }
}

// Constantes adicionais calculadas
define('UPLOAD_MAX_SIZE_FORMATTED', formatBytes(UPLOAD_MAX_SIZE));
define('SYSTEM_INITIALIZED', true);

/* 
==============================================
 INSTRUÇÕES DE CONFIGURAÇÃO:
==============================================

1. ALTERE AS CONFIGURAÇÕES DO BANCO:
   - DB_USER: seu usuário MySQL
   - DB_PASS: sua senha MySQL
   - DB_HOST: normalmente 'localhost'

2. CRIE O BANCO DE DADOS:
   CREATE DATABASE condominio_vitoria_regia CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

3. PERMISSÕES DE PASTA:
   chmod 755 uploads/
   chmod 755 logs/

4. CONFIGURAÇÕES PHP RECOMENDADAS:
   upload_max_filesize = 10M
   post_max_size = 10M
   max_execution_time = 300
   memory_limit = 256M

5. PARA PRODUÇÃO:
   - DEBUG_MODE = false
   - Configurar HTTPS
   - Configurar backup automático
   - Monitorar logs regularmente

==============================================
*/
?>