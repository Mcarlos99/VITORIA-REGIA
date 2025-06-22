<?php
/**
 * Teste específico de execução do login_api.php
 */

// Ativar captura de erros
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Configurar headers como JSON para simular
header('Content-Type: application/json');

echo json_encode(['test' => 'inicio']) . "\n";

// Simular environment de requisição POST
$_SERVER['REQUEST_METHOD'] = 'POST';
$_SERVER['CONTENT_TYPE'] = 'application/json';

// Simular dados de entrada
$test_input = json_encode([
    'action' => 'check'
]);

// Função para capturar a saída do login_api.php
function captureLoginAPI() {
    // Backup dos dados originais
    $original_method = $_SERVER['REQUEST_METHOD'] ?? '';
    $original_input = file_get_contents('php://input');
    
    // Configurar environment
    $_SERVER['REQUEST_METHOD'] = 'POST';
    
    // Simular input
    $test_data = json_encode(['action' => 'check']);
    
    ob_start();
    
    try {
        // Tentar executar o conteúdo do login_api.php
        include 'login_api.php';
        $output = ob_get_contents();
        ob_end_clean();
        
        return [
            'success' => true,
            'output' => $output
        ];
        
    } catch (Exception $e) {
        ob_end_clean();
        return [
            'success' => false,
            'error' => $e->getMessage(),
            'file' => $e->getFile(),
            'line' => $e->getLine()
        ];
    } catch (Error $e) {
        ob_end_clean();
        return [
            'success' => false,
            'error' => 'Fatal Error: ' . $e->getMessage(),
            'file' => $e->getFile(),
            'line' => $e->getLine()
        ];
    } finally {
        // Restaurar environment
        $_SERVER['REQUEST_METHOD'] = $original_method;
    }
}

// Executar teste
echo json_encode(['test' => 'executando_login_api']) . "\n";

$result = captureLoginAPI();

echo json_encode([
    'test' => 'resultado',
    'result' => $result
]) . "\n";

// Verificar logs de erro
echo json_encode(['test' => 'verificando_logs']) . "\n";

$error_log_file = 'logs/error.log';
if (file_exists($error_log_file)) {
    $error_content = file_get_contents($error_log_file);
    $recent_errors = '';
    
    // Pegar apenas as últimas linhas (últimos 2000 caracteres)
    if (strlen($error_content) > 2000) {
        $recent_errors = substr($error_content, -2000);
    } else {
        $recent_errors = $error_content;
    }
    
    echo json_encode([
        'test' => 'logs_encontrados',
        'recent_errors' => $recent_errors
    ]) . "\n";
} else {
    echo json_encode(['test' => 'logs_nao_encontrados']) . "\n";
}

echo json_encode(['test' => 'fim']) . "\n";
?>