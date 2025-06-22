<?php
/**
 * Teste de requisição HTTP real para login_api.php
 */

header('Content-Type: application/json');

// Função para fazer requisição HTTP interna
function makeInternalRequest($url, $data) {
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/json' . "\r\n",
            'content' => json_encode($data),
            'timeout' => 10
        ]
    ]);
    
    $result = @file_get_contents($url, false, $context);
    
    if ($result === false) {
        $error = error_get_last();
        return [
            'success' => false,
            'error' => 'Requisição falhou: ' . ($error['message'] ?? 'Erro desconhecido'),
            'http_response_header' => $http_response_header ?? []
        ];
    }
    
    return [
        'success' => true,
        'response' => $result,
        'headers' => $http_response_header ?? []
    ];
}

// Construir URL completa
$protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'];
$path = dirname($_SERVER['REQUEST_URI']);
$login_api_url = $protocol . '://' . $host . $path . '/login_api.php';

echo json_encode([
    'test' => 'inicio',
    'url' => $login_api_url,
    'timestamp' => date('Y-m-d H:i:s')
]) . "\n";

// Teste 1: Requisição simples de check
echo json_encode(['test' => 'teste_check']) . "\n";

$result1 = makeInternalRequest($login_api_url, ['action' => 'check']);
echo json_encode([
    'test' => 'resultado_check',
    'result' => $result1
]) . "\n";

// Teste 2: Requisição inválida (para ver como lida com erros)
echo json_encode(['test' => 'teste_invalid']) . "\n";

$result2 = makeInternalRequest($login_api_url, ['action' => 'invalid']);
echo json_encode([
    'test' => 'resultado_invalid',
    'result' => $result2
]) . "\n";

// Teste 3: Requisição vazia
echo json_encode(['test' => 'teste_empty']) . "\n";

$result3 = makeInternalRequest($login_api_url, []);
echo json_encode([
    'test' => 'resultado_empty',
    'result' => $result3
]) . "\n";

// Teste 4: Usando cURL (mais robusto)
echo json_encode(['test' => 'teste_curl']) . "\n";

if (function_exists('curl_init')) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $login_api_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['action' => 'check']));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'User-Agent: Internal-Test/1.0'
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HEADER, true);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    echo json_encode([
        'test' => 'resultado_curl',
        'http_code' => $http_code,
        'response' => $response,
        'error' => $error
    ]) . "\n";
} else {
    echo json_encode(['test' => 'curl_nao_disponivel']) . "\n";
}

echo json_encode(['test' => 'fim']) . "\n";
?>