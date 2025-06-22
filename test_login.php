<?php
/**
 * Arquivo de teste para diagnosticar problemas de login
 * Acesse: seu-dominio.com/test_login.php
 */

header('Content-Type: application/json; charset=utf-8');
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo json_encode([
    'status' => 'ok',
    'timestamp' => date('Y-m-d H:i:s'),
    'php_version' => PHP_VERSION,
    'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
    'method' => $_SERVER['REQUEST_METHOD'],
    'input' => file_get_contents('php://input'),
    'post_data' => $_POST,
    'get_data' => $_GET
]);

// Teste de arquivos
echo "\n\n<!-- Teste de arquivos -->\n";
$files_to_check = ['config.php', 'auth.php', 'login_api.php'];
foreach ($files_to_check as $file) {
    echo "<!-- $file: " . (file_exists($file) ? 'EXISTS' : 'NOT FOUND') . " -->\n";
}

// Teste de banco de dados
echo "\n<!-- Teste de banco -->\n";
try {
    if (file_exists('config.php')) {
        require_once 'config.php';
        $pdo = getDB();
        echo "<!-- Banco de dados: CONECTADO -->\n";
        
        // Verificar tabelas
        $stmt = $pdo->query("SHOW TABLES");
        $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
        echo "<!-- Tabelas encontradas: " . implode(', ', $tables) . " -->\n";
        
    } else {
        echo "<!-- config.php não encontrado -->\n";
    }
} catch (Exception $e) {
    echo "<!-- Erro no banco: " . $e->getMessage() . " -->\n";
}
?>