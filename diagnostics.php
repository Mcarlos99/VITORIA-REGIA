<?php
/**
 * Script de Diagnóstico do Sistema
 * Acesse: seu-dominio.com/diagnostics.php
 */

// Ativar exibição de erros para diagnóstico
error_reporting(E_ALL);
ini_set('display_errors', 1);

?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnóstico do Sistema - Vitória Régia</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .status { padding: 10px; margin: 10px 0; border-radius: 4px; }
        .ok { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .test-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .code { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Diagnóstico do Sistema Vitória Régia</h1>
        <p>Este script verifica se todos os componentes estão funcionando corretamente.</p>

        <div class="test-section">
            <h2>1. Informações do Servidor</h2>
            <div class="code">
                <strong>PHP Version:</strong> <?php echo PHP_VERSION; ?><br>
                <strong>Server:</strong> <?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?><br>
                <strong>OS:</strong> <?php echo PHP_OS; ?><br>
                <strong>Max Execution Time:</strong> <?php echo ini_get('max_execution_time'); ?>s<br>
                <strong>Memory Limit:</strong> <?php echo ini_get('memory_limit'); ?><br>
                <strong>Upload Max Size:</strong> <?php echo ini_get('upload_max_filesize'); ?><br>
                <strong>Post Max Size:</strong> <?php echo ini_get('post_max_size'); ?>
            </div>
        </div>

        <div class="test-section">
            <h2>2. Extensões PHP Necessárias</h2>
            <?php
            $required_extensions = ['pdo', 'pdo_mysql', 'json', 'session', 'gd', 'fileinfo'];
            foreach ($required_extensions as $ext) {
                $loaded = extension_loaded($ext);
                echo "<div class='status " . ($loaded ? 'ok' : 'error') . "'>";
                echo "<strong>$ext:</strong> " . ($loaded ? '✅ Carregada' : '❌ Não encontrada');
                echo "</div>";
            }
            ?>
        </div>

        <div class="test-section">
            <h2>3. Arquivos do Sistema</h2>
            <?php
            $required_files = [
                'config.php' => 'Configuração principal',
                'auth.php' => 'Sistema de autenticação',
                'api.php' => 'API principal',
                'login_api.php' => 'API de login',
                'index.php' => 'Página principal'
            ];
            
            foreach ($required_files as $file => $description) {
                $exists = file_exists($file);
                $readable = $exists ? is_readable($file) : false;
                echo "<div class='status " . ($exists && $readable ? 'ok' : 'error') . "'>";
                echo "<strong>$file</strong> ($description): ";
                if ($exists && $readable) {
                    echo "✅ OK";
                } elseif ($exists) {
                    echo "⚠️ Existe mas não é legível";
                } else {
                    echo "❌ Não encontrado";
                }
                echo "</div>";
            }
            ?>
        </div>

        <div class="test-section">
            <h2>4. Teste de Configuração</h2>
            <?php
            try {
                require_once 'config.php';
                echo "<div class='status ok'>✅ config.php carregado com sucesso</div>";
                
                // Verificar constantes
                $constants = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS'];
                foreach ($constants as $const) {
                    if (defined($const)) {
                        echo "<div class='status ok'>✅ $const definida</div>";
                    } else {
                        echo "<div class='status error'>❌ $const não definida</div>";
                    }
                }
                
            } catch (Exception $e) {
                echo "<div class='status error'>❌ Erro ao carregar config.php: " . $e->getMessage() . "</div>";
            }
            ?>
        </div>

        <div class="test-section">
            <h2>5. Teste de Banco de Dados</h2>
            <?php
            try {
                if (function_exists('getDB')) {
                    $pdo = getDB();
                    echo "<div class='status ok'>✅ Conexão com banco estabelecida</div>";
                    
                    // Verificar tabelas
                    $tables = ['usuarios', 'casas', 'pagamentos', 'observacoes'];
                    foreach ($tables as $table) {
                        try {
                            $stmt = $pdo->query("SHOW TABLES LIKE '$table'");
                            if ($stmt->fetch()) {
                                echo "<div class='status ok'>✅ Tabela '$table' existe</div>";
                            } else {
                                echo "<div class='status error'>❌ Tabela '$table' não encontrada</div>";
                            }
                        } catch (Exception $e) {
                            echo "<div class='status error'>❌ Erro ao verificar tabela '$table': " . $e->getMessage() . "</div>";
                        }
                    }
                    
                } else {
                    echo "<div class='status error'>❌ Função getDB() não encontrada</div>";
                }
            } catch (Exception $e) {
                echo "<div class='status error'>❌ Erro de banco: " . $e->getMessage() . "</div>";
            }
            ?>
        </div>

        <div class="test-section">
            <h2>6. Teste de Permissões</h2>
            <?php
            $directories = ['uploads/', 'uploads/contratos/', 'uploads/comprovantes/', 'logs/'];
            foreach ($directories as $dir) {
                if (is_dir($dir)) {
                    if (is_writable($dir)) {
                        echo "<div class='status ok'>✅ $dir existe e é gravável</div>";
                    } else {
                        echo "<div class='status warning'>⚠️ $dir existe mas não é gravável</div>";
                    }
                } else {
                    echo "<div class='status warning'>⚠️ $dir não existe (será criado automaticamente)</div>";
                }
            }
            ?>
        </div>

        <div class="test-section">
            <h2>7. Teste da API de Login</h2>
            <button onclick="testLoginAPI()" style="padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">
                Testar API de Login
            </button>
            <div id="api-test-result" style="margin-top: 10px;"></div>
        </div>

        <div class="test-section">
            <h2>8. Próximos Passos</h2>
            <div class="status warning">
                <strong>Se houver erros:</strong><br>
                1. Corrija as extensões PHP faltantes<br>
                2. Verifique as credenciais do banco em config.php<br>
                3. Execute o script install.php se as tabelas não existirem<br>
                4. Configure as permissões das pastas<br>
                5. Verifique os logs de erro do servidor
            </div>
        </div>
    </div>

    <script>
        async function testLoginAPI() {
            const resultDiv = document.getElementById('api-test-result');
            resultDiv.innerHTML = '<div style="color: #666;">Testando...</div>';
            
            try {
                const response = await fetch('login_api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        action: 'check'
                    })
                });
                
                const text = await response.text();
                console.log('Resposta bruta:', text);
                
                try {
                    const data = JSON.parse(text);
                    resultDiv.innerHTML = `<div style="background: #d4edda; color: #155724; padding: 10px; border-radius: 4px;">
                        ✅ API funcionando! Status: ${response.status}<br>
                        Resposta: ${JSON.stringify(data, null, 2)}
                    </div>`;
                } catch (e) {
                    resultDiv.innerHTML = `<div style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px;">
                        ❌ Resposta não é JSON válido<br>
                        Status: ${response.status}<br>
                        Resposta: ${text}
                    </div>`;
                }
                
            } catch (error) {
                resultDiv.innerHTML = `<div style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px;">
                    ❌ Erro na requisição: ${error.message}
                </div>`;
            }
        }
    </script>
</body>
</html>