<?php
/**
 * Verificador de sintaxe dos arquivos PHP
 */

header('Content-Type: text/plain');

$files_to_check = [
    'config.php',
    'auth.php', 
    'login_api.php',
    'api.php',
    'index.php'
];

echo "=== VERIFICAÇÃO DE SINTAXE PHP ===\n\n";

foreach ($files_to_check as $file) {
    echo "Verificando: $file\n";
    
    if (!file_exists($file)) {
        echo "  ❌ Arquivo não encontrado\n\n";
        continue;
    }
    
    // Verificar sintaxe usando php -l
    $output = [];
    $return_code = 0;
    
    exec("php -l $file 2>&1", $output, $return_code);
    
    if ($return_code === 0) {
        echo "  ✅ Sintaxe OK\n";
    } else {
        echo "  ❌ ERRO DE SINTAXE:\n";
        foreach ($output as $line) {
            echo "     $line\n";
        }
    }
    echo "\n";
}

echo "=== VERIFICAÇÃO DE INCLUDES ===\n\n";

// Testar includes individualmente
echo "Testando config.php:\n";
try {
    ob_start();
    include_once 'config.php';
    ob_end_clean();
    echo "  ✅ config.php carregado\n";
} catch (Exception $e) {
    echo "  ❌ Erro em config.php: " . $e->getMessage() . "\n";
} catch (ParseError $e) {
    echo "  ❌ Erro de sintaxe em config.php: " . $e->getMessage() . "\n";
}

echo "\nTestando auth.php:\n";
try {
    ob_start();
    include_once 'auth.php';
    ob_end_clean();
    echo "  ✅ auth.php carregado\n";
} catch (Exception $e) {
    echo "  ❌ Erro em auth.php: " . $e->getMessage() . "\n";
} catch (ParseError $e) {
    echo "  ❌ Erro de sintaxe em auth.php: " . $e->getMessage() . "\n";
}

echo "\n=== INFORMAÇÕES DO SERVIDOR ===\n";
echo "PHP Version: " . PHP_VERSION . "\n";
echo "Error Reporting: " . error_reporting() . "\n";
echo "Display Errors: " . ini_get('display_errors') . "\n";
echo "Log Errors: " . ini_get('log_errors') . "\n";
echo "Error Log: " . ini_get('error_log') . "\n";

echo "\n=== TESTE DE ESCRITA ===\n";
$test_file = 'test_write.tmp';
if (file_put_contents($test_file, 'test')) {
    echo "✅ Escrita permitida\n";
    unlink($test_file);
} else {
    echo "❌ Sem permissão de escrita\n";
}
?>