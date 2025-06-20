<?php
/**
 * Gerador de Hash de Senhas - Condomínio Vitória Régia
 * 
 * Este utilitário permite gerar hashes seguros de senhas para:
 * - Criação de novos usuários
 * - Redefinição de senhas existentes
 * - Teste de força de senhas
 * - Validação de configurações de hash
 * 
 * IMPORTANTE: Este arquivo deve ser removido em produção
 * ou protegido com autenticação adicional.
 */

// Incluir configurações de segurança
require_once 'config.php';

// Verificar se não está em produção
if (!DEBUG_MODE) {
    die('Este utilitário está disponível apenas em modo de desenvolvimento.');
}

// Configurar headers de segurança básicos
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate');

// Processar formulário se enviado
$result = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $action = $_POST['action'] ?? '';
        
        switch ($action) {
            case 'generate_hash':
                $result = generatePasswordHash();
                break;
                
            case 'verify_password':
                $result = verifyPassword();
                break;
                
            case 'test_strength':
                $result = testPasswordStrength();
                break;
                
            case 'create_user':
                $result = createUser();
                break;
                
            case 'update_password':
                $result = updateUserPassword();
                break;
                
            default:
                throw new Exception('Ação inválida');
        }
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

/**
 * Gerar hash de senha
 */
function generatePasswordHash() {
    $password = $_POST['password'] ?? '';
    
    if (empty($password)) {
        throw new Exception('Senha não pode estar vazia');
    }
    
    // Testar força da senha
    $strength = analyzePasswordStrength($password);
    
    // Gerar hash
    $hash = password_hash($password, PASSWORD_DEFAULT);
    
    // Informações do algoritmo
    $info = password_get_info($hash);
    
    return [
        'type' => 'hash_generated',
        'password' => $password,
        'hash' => $hash,
        'algorithm' => $info['algoName'],
        'options' => $info['options'],
        'strength' => $strength,
        'sql_update' => generateSQLUpdate($hash)
    ];
}

/**
 * Verificar senha contra hash
 */
function verifyPassword() {
    $password = $_POST['verify_password'] ?? '';
    $hash = $_POST['hash'] ?? '';
    
    if (empty($password) || empty($hash)) {
        throw new Exception('Senha e hash são obrigatórios');
    }
    
    $isValid = password_verify($password, $hash);
    $needsRehash = password_needs_rehash($hash, PASSWORD_DEFAULT);
    
    return [
        'type' => 'verification',
        'password' => $password,
        'hash' => $hash,
        'is_valid' => $isValid,
        'needs_rehash' => $needsRehash,
        'recommendation' => $needsRehash ? 'Hash está desatualizado, recomenda-se regerar' : 'Hash está atualizado'
    ];
}

/**
 * Testar força da senha
 */
function testPasswordStrength() {
    $password = $_POST['test_password'] ?? '';
    
    if (empty($password)) {
        throw new Exception('Senha não pode estar vazia');
    }
    
    $strength = analyzePasswordStrength($password);
    
    return [
        'type' => 'strength_test',
        'password' => $password,
        'strength' => $strength
    ];
}

/**
 * Criar novo usuário
 */
function createUser() {
    $username = trim($_POST['new_username'] ?? '');
    $password = $_POST['new_password'] ?? '';
    $nome = trim($_POST['new_nome'] ?? '');
    $email = trim($_POST['new_email'] ?? '');
    
    // Validações
    if (empty($username) || empty($password) || empty($nome)) {
        throw new Exception('Username, senha e nome são obrigatórios');
    }
    
    if (strlen($username) < 3) {
        throw new Exception('Username deve ter pelo menos 3 caracteres');
    }
    
    if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception('Email inválido');
    }
    
    // Verificar força da senha
    $strength = analyzePasswordStrength($password);
    if ($strength['score'] < 3) {
        throw new Exception('Senha muito fraca. Use uma senha mais forte.');
    }
    
    // Verificar se usuário já existe
    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE username = ?");
    $stmt->execute([$username]);
    
    if ($stmt->fetch()) {
        throw new Exception('Usuário já existe');
    }
    
    // Criar usuário
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("
        INSERT INTO usuarios (username, password_hash, nome, email, ativo, created_at)
        VALUES (?, ?, ?, ?, 1, NOW())
    ");
    
    $stmt->execute([$username, $hash, $nome, $email]);
    $userId = $pdo->lastInsertId();
    
    return [
        'type' => 'user_created',
        'user_id' => $userId,
        'username' => $username,
        'nome' => $nome,
        'email' => $email,
        'password_strength' => $strength,
        'sql_insert' => "INSERT INTO usuarios (username, password_hash, nome, email, ativo) VALUES ('$username', '$hash', '$nome', '$email', 1)"
    ];
}

/**
 * Atualizar senha de usuário existente
 */
function updateUserPassword() {
    $username = trim($_POST['update_username'] ?? '');
    $newPassword = $_POST['update_password'] ?? '';
    
    if (empty($username) || empty($newPassword)) {
        throw new Exception('Username e nova senha são obrigatórios');
    }
    
    // Verificar se usuário existe
    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT id, username, nome FROM usuarios WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    
    if (!$user) {
        throw new Exception('Usuário não encontrado');
    }
    
    // Verificar força da senha
    $strength = analyzePasswordStrength($newPassword);
    if ($strength['score'] < 3) {
        throw new Exception('Senha muito fraca. Use uma senha mais forte.');
    }
    
    // Atualizar senha
    $hash = password_hash($newPassword, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("UPDATE usuarios SET password_hash = ? WHERE id = ?");
    $stmt->execute([$hash, $user['id']]);
    
    return [
        'type' => 'password_updated',
        'user_id' => $user['id'],
        'username' => $user['username'],
        'nome' => $user['nome'],
        'new_hash' => $hash,
        'password_strength' => $strength,
        'sql_update' => "UPDATE usuarios SET password_hash = '$hash' WHERE username = '$username'"
    ];
}

/**
 * Analisar força da senha
 */
function analyzePasswordStrength($password) {
    $score = 0;
    $feedback = [];
    $criteria = [];
    
    // Comprimento
    $length = strlen($password);
    if ($length >= 8) {
        $score += 1;
        $criteria['length'] = ['passed' => true, 'message' => 'Comprimento adequado (8+ caracteres)'];
    } else {
        $criteria['length'] = ['passed' => false, 'message' => 'Muito curta (mínimo 8 caracteres)'];
        $feedback[] = 'Use pelo menos 8 caracteres';
    }
    
    if ($length >= 12) {
        $score += 1;
        $criteria['long_length'] = ['passed' => true, 'message' => 'Comprimento excelente (12+ caracteres)'];
    }
    
    // Letras minúsculas
    if (preg_match('/[a-z]/', $password)) {
        $score += 1;
        $criteria['lowercase'] = ['passed' => true, 'message' => 'Contém letras minúsculas'];
    } else {
        $criteria['lowercase'] = ['passed' => false, 'message' => 'Sem letras minúsculas'];
        $feedback[] = 'Adicione letras minúsculas';
    }
    
    // Letras maiúsculas
    if (preg_match('/[A-Z]/', $password)) {
        $score += 1;
        $criteria['uppercase'] = ['passed' => true, 'message' => 'Contém letras maiúsculas'];
    } else {
        $criteria['uppercase'] = ['passed' => false, 'message' => 'Sem letras maiúsculas'];
        $feedback[] = 'Adicione letras maiúsculas';
    }
    
    // Números
    if (preg_match('/[0-9]/', $password)) {
        $score += 1;
        $criteria['numbers'] = ['passed' => true, 'message' => 'Contém números'];
    } else {
        $criteria['numbers'] = ['passed' => false, 'message' => 'Sem números'];
        $feedback[] = 'Adicione números';
    }
    
    // Caracteres especiais
    if (preg_match('/[^a-zA-Z0-9]/', $password)) {
        $score += 1;
        $criteria['special'] = ['passed' => true, 'message' => 'Contém caracteres especiais'];
    } else {
        $criteria['special'] = ['passed' => false, 'message' => 'Sem caracteres especiais'];
        $feedback[] = 'Adicione caracteres especiais (!@#$%^&*)';
    }
    
    // Verificar senhas comuns
    $commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', 'admin', 'root', 'user', 'test', 'vitoria',
        'condominio', 'vitoriaregia', '12345678'
    ];
    
    if (!in_array(strtolower($password), $commonPasswords)) {
        $score += 1;
        $criteria['not_common'] = ['passed' => true, 'message' => 'Não é uma senha comum'];
    } else {
        $criteria['not_common'] = ['passed' => false, 'message' => 'Senha muito comum'];
        $feedback[] = 'Evite senhas comuns e previsíveis';
    }
    
    // Verificar repetições
    if (!preg_match('/(.)\1{2,}/', $password)) {
        $score += 1;
        $criteria['no_repetition'] = ['passed' => true, 'message' => 'Sem repetições excessivas'];
    } else {
        $criteria['no_repetition'] = ['passed' => false, 'message' => 'Muitas repetições'];
        $feedback[] = 'Evite repetir o mesmo caractere';
    }
    
    // Definir nível de força
    $levels = [
        0 => ['name' => 'Muito Fraca', 'color' => '#dc3545', 'width' => '20%'],
        1 => ['name' => 'Fraca', 'color' => '#fd7e14', 'width' => '30%'],
        2 => ['name' => 'Regular', 'color' => '#ffc107', 'width' => '50%'],
        3 => ['name' => 'Boa', 'color' => '#20c997', 'width' => '70%'],
        4 => ['name' => 'Forte', 'color' => '#28a745', 'width' => '85%'],
        5 => ['name' => 'Muito Forte', 'color' => '#198754', 'width' => '100%']
    ];
    
    $maxScore = min($score, 5);
    $strength = $levels[$maxScore];
    
    return [
        'score' => $score,
        'max_score' => 8,
        'percentage' => round(($score / 8) * 100),
        'level' => $strength,
        'criteria' => $criteria,
        'feedback' => $feedback,
        'entropy' => calculateEntropy($password)
    ];
}

/**
 * Calcular entropia da senha
 */
function calculateEntropy($password) {
    $length = strlen($password);
    $charset = 0;
    
    if (preg_match('/[a-z]/', $password)) $charset += 26;
    if (preg_match('/[A-Z]/', $password)) $charset += 26;
    if (preg_match('/[0-9]/', $password)) $charset += 10;
    if (preg_match('/[^a-zA-Z0-9]/', $password)) $charset += 32;
    
    $entropy = $length * log($charset, 2);
    
    return [
        'bits' => round($entropy, 2),
        'charset_size' => $charset,
        'quality' => $entropy >= 60 ? 'Excelente' : ($entropy >= 40 ? 'Boa' : 'Fraca')
    ];
}

/**
 * Gerar SQL de atualização
 */
function generateSQLUpdate($hash) {
    return "UPDATE usuarios SET password_hash = '$hash' WHERE username = 'admin';";
}

/**
 * Listar usuários existentes
 */
function getExistingUsers() {
    try {
        $pdo = getDB();
        $stmt = $pdo->query("
            SELECT id, username, nome, email, ativo, ultimo_login, created_at 
            FROM usuarios 
            ORDER BY created_at DESC
        ");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        return [];
    }
}

$existingUsers = getExistingUsers();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gerador de Senhas - Condomínio Vitória Régia</title>
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
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .warning {
            background: #fff3cd;
            color: #856404;
            padding: 15px;
            border-left: 4px solid #ffc107;
            margin: 20px;
            border-radius: 5px;
        }

        .content {
            padding: 30px;
        }

        .tabs {
            display: flex;
            border-bottom: 2px solid #e0e0e0;
            margin-bottom: 30px;
        }

        .tab {
            padding: 15px 25px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            color: #666;
            transition: all 0.3s ease;
        }

        .tab.active {
            background: #2C5530;
            color: white;
            border-radius: 10px 10px 0 0;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
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

        .result-box {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            border-left: 4px solid #28a745;
        }

        .error-box {
            background: #f8d7da;
            color: #721c24;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            border-left: 4px solid #dc3545;
        }

        .strength-meter {
            height: 10px;
            background: #e0e0e0;
            border-radius: 5px;
            overflow: hidden;
            margin: 10px 0;
        }

        .strength-bar {
            height: 100%;
            transition: all 0.3s ease;
        }

        .criteria-list {
            list-style: none;
            margin: 15px 0;
        }

        .criteria-list li {
            padding: 5px 0;
            display: flex;
            align-items: center;
        }

        .criteria-list li.passed {
            color: #28a745;
        }

        .criteria-list li.failed {
            color: #dc3545;
        }

        .criteria-list li::before {
            content: "✓";
            margin-right: 10px;
            font-weight: bold;
        }

        .criteria-list li.failed::before {
            content: "✗";
        }

        .code-block {
            background: #1e1e1e;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
            margin: 10px 0;
        }

        .user-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        .user-table th,
        .user-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }

        .user-table th {
            background: #f8f9fa;
            font-weight: 600;
        }

        .status-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-active {
            background: #d4edda;
            color: #155724;
        }

        .status-inactive {
            background: #f8d7da;
            color: #721c24;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        @media (max-width: 768px) {
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .tabs {
                flex-wrap: wrap;
            }
            
            .tab {
                flex: 1;
                min-width: 120px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Gerador de Senhas</h1>
            <p>Utilitário de Desenvolvimento - Condomínio Vitória Régia</p>
        </div>

        <div class="warning">
            <strong>⚠️ ATENÇÃO:</strong> Este utilitário é apenas para desenvolvimento. 
            Remova este arquivo em produção ou proteja com autenticação adicional.
        </div>

        <div class="content">
            <div class="tabs">
                <button class="tab active" onclick="showTab('generate')">🔧 Gerar Hash</button>
                <button class="tab" onclick="showTab('verify')">✅ Verificar</button>
                <button class="tab" onclick="showTab('strength')">💪 Força</button>
                <button class="tab" onclick="showTab('create')">👤 Criar Usuário</button>
                <button class="tab" onclick="showTab('update')">🔄 Atualizar</button>
                <button class="tab" onclick="showTab('users')">📋 Usuários</button>
            </div>

            <?php if ($error): ?>
                <div class="error-box">
                    <strong>Erro:</strong> <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <?php if ($result): ?>
                <div class="result-box">
                    <?php renderResult($result); ?>
                </div>
            <?php endif; ?>

            <!-- Aba Gerar Hash -->
            <div id="tab-generate" class="tab-content active">
                <h3>🔧 Gerar Hash de Senha</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="generate_hash">
                    
                    <div class="form-group">
                        <label class="form-label">Senha</label>
                        <input type="text" name="password" class="form-control" 
                               placeholder="Digite a senha para gerar o hash" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">🔧 Gerar Hash</button>
                </form>
            </div>

            <!-- Aba Verificar -->
            <div id="tab-verify" class="tab-content">
                <h3>✅ Verificar Senha contra Hash</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="verify_password">
                    
                    <div class="form-group">
                        <label class="form-label">Senha</label>
                        <input type="text" name="verify_password" class="form-control" 
                               placeholder="Digite a senha" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Hash</label>
                        <textarea name="hash" class="form-control" rows="3" 
                                  placeholder="Cole o hash aqui" required></textarea>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">✅ Verificar</button>
                </form>
            </div>

            <!-- Aba Força -->
            <div id="tab-strength" class="tab-content">
                <h3>💪 Testar Força da Senha</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="test_strength">
                    
                    <div class="form-group">
                        <label class="form-label">Senha</label>
                        <input type="text" name="test_password" class="form-control" 
                               placeholder="Digite a senha para testar" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">💪 Testar Força</button>
                </form>
            </div>

            <!-- Aba Criar Usuário -->
            <div id="tab-create" class="tab-content">
                <h3>👤 Criar Novo Usuário</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="create_user">
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Username</label>
                            <input type="text" name="new_username" class="form-control" 
                                   placeholder="nome_usuario" required>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Nome Completo</label>
                            <input type="text" name="new_nome" class="form-control" 
                                   placeholder="Nome Completo" required>
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Email (opcional)</label>
                            <input type="email" name="new_email" class="form-control" 
                                   placeholder="email@exemplo.com">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Senha</label>
                            <input type="text" name="new_password" class="form-control" 
                                   placeholder="Senha forte" required>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">👤 Criar Usuário</button>
                </form>
            </div>

            <!-- Aba Atualizar -->
            <div id="tab-update" class="tab-content">
                <h3>🔄 Atualizar Senha de Usuário</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="update_password">
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Username</label>
                            <input type="text" name="update_username" class="form-control" 
                                   placeholder="nome_usuario" required>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Nova Senha</label>
                            <input type="text" name="update_password" class="form-control" 
                                   placeholder="Nova senha forte" required>
                        </div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">🔄 Atualizar Senha</button>
                </form>
            </div>

            <!-- Aba Usuários -->
            <div id="tab-users" class="tab-content">
                <h3>📋 Usuários Existentes</h3>
                
                <?php if (empty($existingUsers)): ?>
                    <p>Nenhum usuário encontrado no banco de dados.</p>
                <?php else: ?>
                    <table class="user-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Nome</th>
                                <th>Email</th>
                                <th>Status</th>
                                <th>Último Login</th>
                                <th>Criado em</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($existingUsers as $user): ?>
                                <tr>
                                    <td><?php echo $user['id']; ?></td>
                                    <td><strong><?php echo htmlspecialchars($user['username']); ?></strong></td>
                                    <td><?php echo htmlspecialchars($user['nome']); ?></td>
                                    <td><?php echo htmlspecialchars($user['email'] ?: '-'); ?></td>
                                    <td>
                                        <span class="status-badge <?php echo $user['ativo'] ? 'status-active' : 'status-inactive'; ?>">
                                            <?php echo $user['ativo'] ? 'Ativo' : 'Inativo'; ?>
                                        </span>
                                    </td>
                                    <td><?php echo $user['ultimo_login'] ? date('d/m/Y H:i', strtotime($user['ultimo_login'])) : 'Nunca'; ?></td>
                                    <td><?php echo date('d/m/Y H:i', strtotime($user['created_at'])); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        function showTab(tabName) {
            // Esconder todas as abas
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remover classe active de todos os botões
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Mostrar aba selecionada
            document.getElementById('tab-' + tabName).classList.add('active');
            event.target.classList.add('active');
        }

        // Gerador de senha segura
        function generateSecurePassword() {
            const length = 16;
            const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
            let password = "";
            
            // Garantir pelo menos um de cada tipo
            password += "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)];
            password += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[Math.floor(Math.random() * 26)];
            password += "0123456789"[Math.floor(Math.random() * 10)];
            password += "!@#$%^&*"[Math.floor(Math.random() * 8)];
            
            // Preencher o resto
            for (let i = 4; i < length; i++) {
                password += charset[Math.floor(Math.random() * charset.length)];
            }
            
            // Embaralhar
            return password.split('').sort(() => Math.random() - 0.5).join('');
        }

        // Adicionar botões de gerar senha
        document.addEventListener('DOMContentLoaded', function() {
            const passwordFields = document.querySelectorAll('input[name*="password"]:not([name*="verify"]):not([name*="update_username"])');
            
            passwordFields.forEach(field => {
                if (field.type === 'text') {
                    const button = document.createElement('button');
                    button.type = 'button';
                    button.textContent = '🎲 Gerar';
                    button.className = 'btn btn-primary';
                    button.style.marginLeft = '10px';
                    button.style.padding = '8px 16px';
                    button.style.fontSize = '14px';
                    
                    button.onclick = function() {
                        field.value = generateSecurePassword();
                    };
                    
                    field.parentNode.appendChild(button);
                }
            });
        });

        // Copiar para clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('Copiado para a área de transferência!');
            }).catch(function() {
                // Fallback para navegadores mais antigos
                const textarea = document.createElement('textarea');
                textarea.value = text;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                alert('Copiado para a área de transferência!');
            });
        }
    </script>
</body>
</html>

<?php
/**
 * Renderizar resultado baseado no tipo
 */
function renderResult($result) {
    switch ($result['type']) {
        case 'hash_generated':
            renderHashGenerated($result);
            break;
            
        case 'verification':
            renderVerification($result);
            break;
            
        case 'strength_test':
            renderStrengthTest($result);
            break;
            
        case 'user_created':
            renderUserCreated($result);
            break;
            
        case 'password_updated':
            renderPasswordUpdated($result);
            break;
    }
}

/**
 * Renderizar resultado de hash gerado
 */
function renderHashGenerated($result) {
    echo "<h4>✅ Hash Gerado com Sucesso</h4>";
    echo "<p><strong>Senha:</strong> <code>" . htmlspecialchars($result['password']) . "</code></p>";
    echo "<p><strong>Algoritmo:</strong> " . $result['algorithm'] . "</p>";
    
    echo "<div class='form-group'>";
    echo "<label class='form-label'>Hash Gerado:</label>";
    echo "<div class='code-block' onclick=\"copyToClipboard('" . htmlspecialchars($result['hash']) . "')\" style='cursor: pointer; border: 2px dashed #28a745;'>";
    echo htmlspecialchars($result['hash']);
    echo "<br><small style='color: #28a745;'>Clique para copiar</small>";
    echo "</div>";
    echo "</div>";
    
    echo "<div class='form-group'>";
    echo "<label class='form-label'>SQL para Atualizar:</label>";
    echo "<div class='code-block' onclick=\"copyToClipboard('" . htmlspecialchars($result['sql_update']) . "')\" style='cursor: pointer; border: 2px dashed #007bff;'>";
    echo htmlspecialchars($result['sql_update']);
    echo "<br><small style='color: #007bff;'>Clique para copiar</small>";
    echo "</div>";
    echo "</div>";
    
    renderStrengthAnalysis($result['strength']);
}

/**
 * Renderizar resultado de verificação
 */
function renderVerification($result) {
    echo "<h4>" . ($result['is_valid'] ? "✅ Senha Válida" : "❌ Senha Inválida") . "</h4>";
    echo "<p><strong>Senha:</strong> <code>" . htmlspecialchars($result['password']) . "</code></p>";
    echo "<p><strong>Resultado:</strong> " . ($result['is_valid'] ? "✅ Corresponde ao hash" : "❌ Não corresponde ao hash") . "</p>";
    
    if ($result['needs_rehash']) {
        echo "<div style='background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 10px 0;'>";
        echo "<strong>⚠️ Atenção:</strong> " . $result['recommendation'];
        echo "</div>";
    }
}

/**
 * Renderizar teste de força
 */
function renderStrengthTest($result) {
    echo "<h4>💪 Análise de Força da Senha</h4>";
    echo "<p><strong>Senha:</strong> <code>" . htmlspecialchars($result['password']) . "</code></p>";
    
    renderStrengthAnalysis($result['strength']);
}

/**
 * Renderizar usuário criado
 */
function renderUserCreated($result) {
    echo "<h4>✅ Usuário Criado com Sucesso</h4>";
    echo "<p><strong>ID:</strong> " . $result['user_id'] . "</p>";
    echo "<p><strong>Username:</strong> <code>" . htmlspecialchars($result['username']) . "</code></p>";
    echo "<p><strong>Nome:</strong> " . htmlspecialchars($result['nome']) . "</p>";
    echo "<p><strong>Email:</strong> " . htmlspecialchars($result['email'] ?: 'Não informado') . "</p>";
    
    echo "<div class='form-group'>";
    echo "<label class='form-label'>SQL Executado:</label>";
    echo "<div class='code-block'>";
    echo htmlspecialchars($result['sql_insert']);
    echo "</div>";
    echo "</div>";
    
    renderStrengthAnalysis($result['password_strength']);
}

/**
 * Renderizar senha atualizada
 */
function renderPasswordUpdated($result) {
    echo "<h4>✅ Senha Atualizada com Sucesso</h4>";
    echo "<p><strong>Usuário:</strong> " . htmlspecialchars($result['username']) . " (" . htmlspecialchars($result['nome']) . ")</p>";
    
    echo "<div class='form-group'>";
    echo "<label class='form-label'>Novo Hash:</label>";
    echo "<div class='code-block' onclick=\"copyToClipboard('" . htmlspecialchars($result['new_hash']) . "')\" style='cursor: pointer; border: 2px dashed #28a745;'>";
    echo htmlspecialchars($result['new_hash']);
    echo "<br><small style='color: #28a745;'>Clique para copiar</small>";
    echo "</div>";
    echo "</div>";
    
    echo "<div class='form-group'>";
    echo "<label class='form-label'>SQL Executado:</label>";
    echo "<div class='code-block'>";
    echo htmlspecialchars($result['sql_update']);
    echo "</div>";
    echo "</div>";
    
    renderStrengthAnalysis($result['password_strength']);
}

/**
 * Renderizar análise de força
 */
function renderStrengthAnalysis($strength) {
    echo "<div style='margin: 20px 0;'>";
    echo "<h5>Análise de Força</h5>";
    
    // Barra de força
    echo "<div class='strength-meter'>";
    echo "<div class='strength-bar' style='width: " . $strength['level']['width'] . "; background: " . $strength['level']['color'] . ";'></div>";
    echo "</div>";
    
    echo "<p><strong>Nível:</strong> <span style='color: " . $strength['level']['color'] . ";'>" . $strength['level']['name'] . "</span></p>";
    echo "<p><strong>Pontuação:</strong> " . $strength['score'] . "/" . $strength['max_score'] . " (" . $strength['percentage'] . "%)</p>";
    echo "<p><strong>Entropia:</strong> " . $strength['entropy']['bits'] . " bits (" . $strength['entropy']['quality'] . ")</p>";
    
    // Critérios
    echo "<h6>Critérios de Validação:</h6>";
    echo "<ul class='criteria-list'>";
    foreach ($strength['criteria'] as $criterion) {
        $class = $criterion['passed'] ? 'passed' : 'failed';
        echo "<li class='$class'>" . $criterion['message'] . "</li>";
    }
    echo "</ul>";
    
    // Feedback
    if (!empty($strength['feedback'])) {
        echo "<h6>Sugestões para Melhorar:</h6>";
        echo "<ul>";
        foreach ($strength['feedback'] as $suggestion) {
            echo "<li style='color: #dc3545;'>" . $suggestion . "</li>";
        }
        echo "</ul>";
    }
    echo "</div>";
}

/*
==============================================
 EXEMPLOS DE SENHAS SEGURAS:
==============================================

Muito Forte (Score 7-8):
- MyP@ssw0rd123!
- Tr0ub4dor&3
- C0ndom1n10*V1t0r14

Forte (Score 5-6):
- MinhaSenh@123
- V1tor1aReg1a!
- Admin2025#

Regular (Score 3-4):
- vitoria123
- Admin2025
- password!

Fraca (Score 1-2):
- 123456
- password
- admin

==============================================
 COMANDOS SQL ÚTEIS:
==============================================

-- Criar usuário admin padrão
INSERT INTO usuarios (username, password_hash, nome, email, ativo) 
VALUES ('admin', '$2y$10$...', 'Administrador', 'admin@vitoriaregia.com', 1);

-- Atualizar senha do admin
UPDATE usuarios SET password_hash = '$2y$10$...' WHERE username = 'admin';

-- Listar todos os usuários
SELECT id, username, nome, email, ativo, ultimo_login, created_at FROM usuarios;

-- Desativar usuário
UPDATE usuarios SET ativo = 0 WHERE username = 'usuario';

-- Remover usuário
DELETE FROM usuarios WHERE username = 'usuario';

==============================================
 INSTRUÇÕES DE SEGURANÇA:
==============================================

1. REMOVER EM PRODUÇÃO:
   - Delete este arquivo antes do deploy
   - Ou mova para pasta protegida

2. SENHAS SEGURAS:
   - Mínimo 8 caracteres
   - Maiúsculas + minúsculas + números + símbolos
   - Evitar palavras comuns
   - Usar geradores aleatórios

3. POLÍTICAS DE SENHA:
   - Trocar senhas a cada 90 dias
   - Não reutilizar últimas 5 senhas
   - Bloquear após 5 tentativas

4. MONITORAMENTO:
   - Verificar logs de login
   - Monitorar tentativas de força bruta
   - Alertas para atividades suspeitas

==============================================
*/
?>