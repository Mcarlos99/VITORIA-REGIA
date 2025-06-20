<?php
/**
 * API Principal - Condomínio Vitória Régia
 * 
 * Esta API gerencia todas as operações CRUD do sistema:
 * - Casas e moradores
 * - Pagamentos e comprovantes
 * - Observações e reparos
 * - Relatórios gerenciais
 * 
 * Rotas disponíveis:
 * GET    /api/casas           - Listar todas as casas
 * POST   /api/casas           - Atualizar dados de uma casa
 * DELETE /api/casas/{id}      - Remover morador de uma casa
 * 
 * GET    /api/pagamentos      - Listar pagamentos
 * POST   /api/pagamentos      - Criar novo pagamento
 * PUT    /api/pagamentos/{id} - Atualizar pagamento
 * DELETE /api/pagamentos/{id} - Excluir pagamento
 * 
 * GET    /api/observacoes     - Listar observações
 * POST   /api/observacoes     - Criar observação
 * PUT    /api/observacoes/{id}- Atualizar observação
 * DELETE /api/observacoes/{id}- Excluir observação
 * 
 * GET    /api/relatorios      - Obter dados para relatórios
 */

require_once 'config.php';
require_once 'auth.php';

// Verificar autenticação para todas as operações
$auth = authMiddleware();

// Configurar headers
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

// Tratar requisições OPTIONS (preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Obter conexão com banco
$pdo = getDB();

// Processar rota
$method = $_SERVER['REQUEST_METHOD'];
$path = $_SERVER['PATH_INFO'] ?? '';
$segments = explode('/', trim($path, '/'));
$resource = $segments[0] ?? '';
$id = $segments[1] ?? null;

// Log da requisição
logActivity("API Request: $method $path", 'INFO', [
    'user' => getCurrentUser()['username'] ?? 'unknown',
    'ip' => $_SERVER['REMOTE_ADDR']
]);

try {
    switch ($resource) {
        case 'casas':
            handleCasas($method, $id, $pdo);
            break;
            
        case 'pagamentos':
            handlePagamentos($method, $id, $pdo);
            break;
            
        case 'observacoes':
            handleObservacoes($method, $id, $pdo);
            break;
            
        case 'relatorios':
            handleRelatorios($method, $pdo);
            break;
            
        case 'upload':
            handleUpload($method, $pdo);
            break;
            
        default:
            throw new Exception('Recurso não encontrado', 404);
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
    error_log("API Error: " . $e->getMessage() . " - Route: $method $path");
}

/**
 * Gerenciar operações de Casas
 */
function handleCasas($method, $id, $pdo) {
    switch ($method) {
        case 'GET':
            if ($id) {
                // Buscar casa específica
                $stmt = $pdo->prepare("SELECT * FROM casas WHERE id = ?");
                $stmt->execute([$id]);
                $casa = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$casa) {
                    throw new Exception('Casa não encontrada', 404);
                }
                
                echo json_encode(['success' => true, 'data' => $casa]);
            } else {
                // Listar todas as casas
                $stmt = $pdo->query("
                    SELECT 
                        c.*,
                        COUNT(DISTINCT p.id) as total_pagamentos,
                        COUNT(DISTINCT CASE WHEN p.status = 'pago' THEN p.id END) as pagamentos_pagos,
                        COUNT(DISTINCT CASE WHEN p.status = 'pendente' THEN p.id END) as pagamentos_pendentes,
                        COUNT(DISTINCT CASE WHEN p.status = 'atrasado' THEN p.id END) as pagamentos_atrasados,
                        COUNT(DISTINCT o.id) as total_observacoes,
                        COUNT(DISTINCT CASE WHEN o.status != 'resolvida' THEN o.id END) as observacoes_pendentes
                    FROM casas c
                    LEFT JOIN pagamentos p ON c.id = p.casa_id
                    LEFT JOIN observacoes o ON c.id = o.casa_id
                    GROUP BY c.id
                    ORDER BY c.numero
                ");
                
                $casas = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                echo json_encode(['success' => true, 'data' => $casas]);
            }
            break;
            
        case 'POST':
            $data = json_decode(file_get_contents('php://input'), true);
            
            if (!$data || !isset($data['id'])) {
                throw new Exception('Dados inválidos', 400);
            }
            
            // Validar dados
            $requiredFields = ['morador', 'telefone', 'contrato_inicio', 'contrato_fim', 'valor_mensal'];
            foreach ($requiredFields as $field) {
                if (empty($data[$field])) {
                    throw new Exception("Campo '$field' é obrigatório", 400);
                }
            }
            
            // Validar formato de data
            if (!validateDate($data['contrato_inicio']) || !validateDate($data['contrato_fim'])) {
                throw new Exception('Formato de data inválido', 400);
            }
            
            // Validar valor mensal
            if (!is_numeric($data['valor_mensal']) || $data['valor_mensal'] <= 0) {
                throw new Exception('Valor mensal deve ser um número positivo', 400);
            }
            
            $stmt = $pdo->prepare("
                UPDATE casas SET 
                    morador = ?, 
                    telefone = ?, 
                    contrato_inicio = ?, 
                    contrato_fim = ?, 
                    valor_mensal = ?, 
                    arquivo_contrato = ?,
                    updated_at = NOW()
                WHERE id = ?
            ");
            
            $stmt->execute([
                $data['morador'],
                $data['telefone'],
                $data['contrato_inicio'],
                $data['contrato_fim'],
                $data['valor_mensal'],
                $data['arquivo_contrato'] ?? null,
                $data['id']
            ]);
            
            logActivity("Casa atualizada: Casa {$data['id']} - {$data['morador']}", 'INFO');
            
            echo json_encode(['success' => true, 'message' => 'Casa atualizada com sucesso']);
            break;
            
        case 'DELETE':
            if (!$id) {
                throw new Exception('ID da casa é obrigatório', 400);
            }
            
            // Obter dados da casa antes de remover
            $stmt = $pdo->prepare("SELECT numero, morador FROM casas WHERE id = ?");
            $stmt->execute([$id]);
            $casa = $stmt->fetch();
            
            if (!$casa) {
                throw new Exception('Casa não encontrada', 404);
            }
            
            // Remover dados do morador (manter a casa)
            $stmt = $pdo->prepare("
                UPDATE casas SET 
                    morador = NULL, 
                    telefone = NULL, 
                    contrato_inicio = NULL,
                    contrato_fim = NULL, 
                    valor_mensal = 0, 
                    arquivo_contrato = NULL,
                    updated_at = NOW()
                WHERE id = ?
            ");
            $stmt->execute([$id]);
            
            logActivity("Morador removido: Casa {$casa['numero']} - {$casa['morador']}", 'INFO');
            
            echo json_encode(['success' => true, 'message' => 'Morador removido com sucesso']);
            break;
            
        default:
            throw new Exception('Método não permitido', 405);
    }
}

/**
 * Gerenciar operações de Pagamentos
 */
function handlePagamentos($method, $id, $pdo) {
    switch ($method) {
        case 'GET':
            if ($id) {
                // Buscar pagamento específico
                $stmt = $pdo->prepare("
                    SELECT p.*, c.numero, c.morador 
                    FROM pagamentos p 
                    JOIN casas c ON p.casa_id = c.id 
                    WHERE p.id = ?
                ");
                $stmt->execute([$id]);
                $pagamento = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$pagamento) {
                    throw new Exception('Pagamento não encontrado', 404);
                }
                
                echo json_encode(['success' => true, 'data' => $pagamento]);
            } else {
                // Listar pagamentos com filtros opcionais
                $where = "1=1";
                $params = [];
                
                if (isset($_GET['casa_id'])) {
                    $where .= " AND p.casa_id = ?";
                    $params[] = $_GET['casa_id'];
                }
                
                if (isset($_GET['mes'])) {
                    $where .= " AND p.mes = ?";
                    $params[] = $_GET['mes'];
                }
                
                if (isset($_GET['ano'])) {
                    $where .= " AND p.ano = ?";
                    $params[] = $_GET['ano'];
                }
                
                if (isset($_GET['status'])) {
                    $where .= " AND p.status = ?";
                    $params[] = $_GET['status'];
                }
                
                $stmt = $pdo->prepare("
                    SELECT p.*, c.numero, c.morador 
                    FROM pagamentos p 
                    JOIN casas c ON p.casa_id = c.id 
                    WHERE $where
                    ORDER BY p.ano DESC, p.mes DESC, c.numero
                ");
                $stmt->execute($params);
                $pagamentos = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                echo json_encode(['success' => true, 'data' => $pagamentos]);
            }
            break;
            
        case 'POST':
            $data = json_decode(file_get_contents('php://input'), true);
            
            if (!$data) {
                throw new Exception('Dados inválidos', 400);
            }
            
            // Validar dados obrigatórios
            $requiredFields = ['casa_id', 'mes', 'ano', 'valor', 'status'];
            foreach ($requiredFields as $field) {
                if (!isset($data[$field]) || $data[$field] === '') {
                    throw new Exception("Campo '$field' é obrigatório", 400);
                }
            }
            
            // Validações específicas
            if (!is_numeric($data['casa_id']) || $data['casa_id'] <= 0) {
                throw new Exception('ID da casa inválido', 400);
            }
            
            if (!is_numeric($data['mes']) || $data['mes'] < 1 || $data['mes'] > 12) {
                throw new Exception('Mês deve ser entre 1 e 12', 400);
            }
            
            if (!is_numeric($data['ano']) || $data['ano'] < 2020 || $data['ano'] > 2030) {
                throw new Exception('Ano inválido', 400);
            }
            
            if (!is_numeric($data['valor']) || $data['valor'] <= 0) {
                throw new Exception('Valor deve ser um número positivo', 400);
            }
            
            if (!in_array($data['status'], ['pendente', 'pago', 'atrasado'])) {
                throw new Exception('Status inválido', 400);
            }
            
            // Verificar se a casa existe
            $stmt = $pdo->prepare("SELECT numero, morador FROM casas WHERE id = ?");
            $stmt->execute([$data['casa_id']]);
            $casa = $stmt->fetch();
            
            if (!$casa) {
                throw new Exception('Casa não encontrada', 404);
            }
            
            // Verificar se já existe pagamento para este mês/ano/casa
            $stmt = $pdo->prepare("
                SELECT id FROM pagamentos 
                WHERE casa_id = ? AND mes = ? AND ano = ?
            ");
            $stmt->execute([$data['casa_id'], $data['mes'], $data['ano']]);
            
            if ($stmt->fetch()) {
                throw new Exception('Já existe um pagamento para esta casa neste período', 409);
            }
            
            // Validar data de pagamento se fornecida
            if (!empty($data['data_pagamento']) && !validateDate($data['data_pagamento'])) {
                throw new Exception('Formato de data de pagamento inválido', 400);
            }
            
            $stmt = $pdo->prepare("
                INSERT INTO pagamentos (casa_id, mes, ano, valor, data_pagamento, status, comprovante) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $data['casa_id'],
                $data['mes'],
                $data['ano'],
                $data['valor'],
                $data['data_pagamento'] ?: null,
                $data['status'],
                $data['comprovante'] ?? null
            ]);
            
            $novoId = $pdo->lastInsertId();
            
            logActivity("Pagamento criado: Casa {$casa['numero']} - {$data['mes']}/{$data['ano']} - R$ {$data['valor']}", 'INFO');
            
            echo json_encode([
                'success' => true, 
                'message' => 'Pagamento criado com sucesso',
                'id' => $novoId
            ]);
            break;
            
        case 'PUT':
            if (!$id) {
                throw new Exception('ID do pagamento é obrigatório', 400);
            }
            
            $data = json_decode(file_get_contents('php://input'), true);
            
            if (!$data) {
                throw new Exception('Dados inválidos', 400);
            }
            
            // Verificar se pagamento existe
            $stmt = $pdo->prepare("SELECT * FROM pagamentos WHERE id = ?");
            $stmt->execute([$id]);
            $pagamento = $stmt->fetch();
            
            if (!$pagamento) {
                throw new Exception('Pagamento não encontrado', 404);
            }
            
            // Validar data de pagamento se fornecida
            if (!empty($data['data_pagamento']) && !validateDate($data['data_pagamento'])) {
                throw new Exception('Formato de data de pagamento inválido', 400);
            }
            
            $stmt = $pdo->prepare("
                UPDATE pagamentos SET 
                    mes = ?, ano = ?, valor = ?, data_pagamento = ?, status = ?, comprovante = ?
                WHERE id = ?
            ");
            
            $stmt->execute([
                $data['mes'] ?? $pagamento['mes'],
                $data['ano'] ?? $pagamento['ano'],
                $data['valor'] ?? $pagamento['valor'],
                $data['data_pagamento'] ?: null,
                $data['status'] ?? $pagamento['status'],
                $data['comprovante'] ?? $pagamento['comprovante'],
                $id
            ]);
            
            logActivity("Pagamento atualizado: ID $id", 'INFO');
            
            echo json_encode(['success' => true, 'message' => 'Pagamento atualizado com sucesso']);
            break;
            
        case 'DELETE':
            if (!$id) {
                throw new Exception('ID do pagamento é obrigatório', 400);
            }
            
            // Buscar dados do pagamento e comprovante
            $stmt = $pdo->prepare("
                SELECT p.*, c.numero 
                FROM pagamentos p 
                JOIN casas c ON p.casa_id = c.id 
                WHERE p.id = ?
            ");
            $stmt->execute([$id]);
            $pagamento = $stmt->fetch();
            
            if (!$pagamento) {
                throw new Exception('Pagamento não encontrado', 404);
            }
            
            // Excluir arquivo de comprovante se existir
            if ($pagamento['comprovante']) {
                $filePath = UPLOAD_DIR_COMPROVANTES . $pagamento['comprovante'];
                if (file_exists($filePath)) {
                    unlink($filePath);
                    logActivity("Comprovante excluído: {$pagamento['comprovante']}", 'INFO');
                }
            }
            
            // Excluir pagamento
            $stmt = $pdo->prepare("DELETE FROM pagamentos WHERE id = ?");
            $stmt->execute([$id]);
            
            logActivity("Pagamento excluído: Casa {$pagamento['numero']} - {$pagamento['mes']}/{$pagamento['ano']}", 'INFO');
            
            echo json_encode(['success' => true, 'message' => 'Pagamento excluído com sucesso']);
            break;
            
        default:
            throw new Exception('Método não permitido', 405);
    }
}

/**
 * Gerenciar operações de Observações
 */
function handleObservacoes($method, $id, $pdo) {
    switch ($method) {
        case 'GET':
            if ($id) {
                // Buscar observação específica
                $stmt = $pdo->prepare("
                    SELECT o.*, c.numero, c.morador 
                    FROM observacoes o 
                    JOIN casas c ON o.casa_id = c.id 
                    WHERE o.id = ?
                ");
                $stmt->execute([$id]);
                $observacao = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$observacao) {
                    throw new Exception('Observação não encontrada', 404);
                }
                
                echo json_encode(['success' => true, 'data' => $observacao]);
            } else {
                // Listar observações com filtros opcionais
                $where = "1=1";
                $params = [];
                
                if (isset($_GET['casa_id'])) {
                    $where .= " AND o.casa_id = ?";
                    $params[] = $_GET['casa_id'];
                }
                
                if (isset($_GET['status'])) {
                    $where .= " AND o.status = ?";
                    $params[] = $_GET['status'];
                }
                
                $stmt = $pdo->prepare("
                    SELECT o.*, c.numero, c.morador 
                    FROM observacoes o 
                    JOIN casas c ON o.casa_id = c.id 
                    WHERE $where
                    ORDER BY o.data DESC, o.created_at DESC
                ");
                $stmt->execute($params);
                $observacoes = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                echo json_encode(['success' => true, 'data' => $observacoes]);
            }
            break;
            
        case 'POST':
            $data = json_decode(file_get_contents('php://input'), true);
            
            if (!$data) {
                throw new Exception('Dados inválidos', 400);
            }
            
            // Validar dados obrigatórios
            $requiredFields = ['casa_id', 'descricao', 'data', 'status'];
            foreach ($requiredFields as $field) {
                if (!isset($data[$field]) || $data[$field] === '') {
                    throw new Exception("Campo '$field' é obrigatório", 400);
                }
            }
            
            // Validações específicas
            if (!is_numeric($data['casa_id']) || $data['casa_id'] <= 0) {
                throw new Exception('ID da casa inválido', 400);
            }
            
            if (!validateDate($data['data'])) {
                throw new Exception('Formato de data inválido', 400);
            }
            
            if (!in_array($data['status'], ['pendente', 'em_andamento', 'resolvida'])) {
                throw new Exception('Status inválido', 400);
            }
            
            if (strlen($data['descricao']) < 5) {
                throw new Exception('Descrição deve ter pelo menos 5 caracteres', 400);
            }
            
            // Verificar se a casa existe
            $stmt = $pdo->prepare("SELECT numero, morador FROM casas WHERE id = ?");
            $stmt->execute([$data['casa_id']]);
            $casa = $stmt->fetch();
            
            if (!$casa) {
                throw new Exception('Casa não encontrada', 404);
            }
            
            $stmt = $pdo->prepare("
                INSERT INTO observacoes (casa_id, descricao, data, status) 
                VALUES (?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $data['casa_id'],
                $data['descricao'],
                $data['data'],
                $data['status']
            ]);
            
            $novoId = $pdo->lastInsertId();
            
            logActivity("Observação criada: Casa {$casa['numero']} - " . substr($data['descricao'], 0, 50) . "...", 'INFO');
            
            echo json_encode([
                'success' => true, 
                'message' => 'Observação criada com sucesso',
                'id' => $novoId
            ]);
            break;
            
        case 'PUT':
            if (!$id) {
                throw new Exception('ID da observação é obrigatório', 400);
            }
            
            $data = json_decode(file_get_contents('php://input'), true);
            
            if (!$data) {
                throw new Exception('Dados inválidos', 400);
            }
            
            // Verificar se observação existe
            $stmt = $pdo->prepare("SELECT * FROM observacoes WHERE id = ?");
            $stmt->execute([$id]);
            $observacao = $stmt->fetch();
            
            if (!$observacao) {
                throw new Exception('Observação não encontrada', 404);
            }
            
            // Validar data se fornecida
            if (!empty($data['data']) && !validateDate($data['data'])) {
                throw new Exception('Formato de data inválido', 400);
            }
            
            $stmt = $pdo->prepare("
                UPDATE observacoes SET 
                    descricao = ?, data = ?, status = ?
                WHERE id = ?
            ");
            
            $stmt->execute([
                $data['descricao'] ?? $observacao['descricao'],
                $data['data'] ?? $observacao['data'],
                $data['status'] ?? $observacao['status'],
                $id
            ]);
            
            logActivity("Observação atualizada: ID $id", 'INFO');
            
            echo json_encode(['success' => true, 'message' => 'Observação atualizada com sucesso']);
            break;
            
        case 'DELETE':
            if (!$id) {
                throw new Exception('ID da observação é obrigatório', 400);
            }
            
            // Verificar se observação existe
            $stmt = $pdo->prepare("
                SELECT o.*, c.numero 
                FROM observacoes o 
                JOIN casas c ON o.casa_id = c.id 
                WHERE o.id = ?
            ");
            $stmt->execute([$id]);
            $observacao = $stmt->fetch();
            
            if (!$observacao) {
                throw new Exception('Observação não encontrada', 404);
            }
            
            $stmt = $pdo->prepare("DELETE FROM observacoes WHERE id = ?");
            $stmt->execute([$id]);
            
            logActivity("Observação excluída: Casa {$observacao['numero']} - " . substr($observacao['descricao'], 0, 50) . "...", 'INFO');
            
            echo json_encode(['success' => true, 'message' => 'Observação excluída com sucesso']);
            break;
            
        default:
            throw new Exception('Método não permitido', 405);
    }
}

/**
 * Gerenciar relatórios
 */
function handleRelatorios($method, $pdo) {
    if ($method !== 'GET') {
        throw new Exception('Método não permitido', 405);
    }
    
    $tipo = $_GET['tipo'] ?? 'geral';
    
    switch ($tipo) {
        case 'geral':
            echo json_encode(['success' => true, 'data' => getRelatorioGeral($pdo)]);
            break;
            
        case 'financeiro':
            $mes = $_GET['mes'] ?? date('n');
            $ano = $_GET['ano'] ?? date('Y');
            echo json_encode(['success' => true, 'data' => getRelatorioFinanceiro($pdo, $mes, $ano)]);
            break;
            
        case 'ocupacao':
            echo json_encode(['success' => true, 'data' => getRelatorioOcupacao($pdo)]);
            break;
            
        default:
            throw new Exception('Tipo de relatório inválido', 400);
    }
}

/**
 * Relatório geral do condomínio
 */
function getRelatorioGeral($pdo) {
    // Estatísticas básicas
    $stmt = $pdo->query("
        SELECT 
            COUNT(*) as total_casas,
            COUNT(CASE WHEN morador IS NOT NULL AND morador != '' THEN 1 END) as casas_ocupadas,
            COUNT(CASE WHEN morador IS NULL OR morador = '' THEN 1 END) as casas_vazias
        FROM casas
    ");
    $estatisticas = $stmt->fetch();
    
    // Observações pendentes
    $stmt = $pdo->query("
        SELECT COUNT(*) as observacoes_pendentes 
        FROM observacoes 
        WHERE status != 'resolvida'
    ");
    $observacoesPendentes = $stmt->fetch()['observacoes_pendentes'];
    
    // Pagamentos do mês atual
    $mesAtual = date('n');
    $anoAtual = date('Y');
    
    $stmt = $pdo->prepare("
        SELECT 
            COUNT(*) as total_pagamentos,
            COUNT(CASE WHEN status = 'pago' THEN 1 END) as pagamentos_pagos,
            COUNT(CASE WHEN status = 'pendente' THEN 1 END) as pagamentos_pendentes,
            COUNT(CASE WHEN status = 'atrasado' THEN 1 END) as pagamentos_atrasados,
            SUM(CASE WHEN status = 'pago' THEN valor ELSE 0 END) as receita_recebida,
            SUM(valor) as receita_esperada
        FROM pagamentos 
        WHERE mes = ? AND ano = ?
    ");
    $stmt->execute([$mesAtual, $anoAtual]);
    $pagamentosDoMes = $stmt->fetch();
    
    return [
        'estatisticas_gerais' => $estatisticas,
        'observacoes_pendentes' => $observacoesPendentes,
        'pagamentos_mes_atual' => $pagamentosDoMes,
        'taxa_ocupacao' => round(($estatisticas['casas_ocupadas'] / $estatisticas['total_casas']) * 100, 1),
        'taxa_recebimento' => $pagamentosDoMes['receita_esperada'] > 0 ? 
            round(($pagamentosDoMes['receita_recebida'] / $pagamentosDoMes['receita_esperada']) * 100, 1) : 0
    ];
}

/**
 * Relatório financeiro por período
 */
function getRelatorioFinanceiro($pdo, $mes, $ano) {
    $stmt = $pdo->prepare("
        SELECT 
            c.numero,
            c.morador,
            c.valor_mensal,
            p.valor as valor_pago,
            p.data_pagamento,
            p.status,
            p.comprovante
        FROM casas c
        LEFT JOIN pagamentos p ON c.id = p.casa_id AND p.mes = ? AND p.ano = ?
        WHERE c.morador IS NOT NULL AND c.morador != ''
        ORDER BY c.numero
    ");
    $stmt->execute([$mes, $ano]);
    $detalhes = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Totais
    $receitaEsperada = array_sum(array_column($detalhes, 'valor_mensal'));
    $receitaRecebida = array_sum(array_filter(array_column($detalhes, 'valor_pago')));
    $pendentes = count(array_filter($detalhes, function($item) { return $item['status'] === 'pendente' || $item['status'] === null; }));
    $atrasados = count(array_filter($detalhes, function($item) { return $item['status'] === 'atrasado'; }));
    
    return [
        'periodo' => sprintf('%02d/%04d', $mes, $ano),
        'receita_esperada' => $receitaEsperada,
        'receita_recebida' => $receitaRecebida,
        'receita_pendente' => $receitaEsperada - $receitaRecebida,
        'pagamentos_pendentes' => $pendentes,
        'pagamentos_atrasados' => $atrasados,
        'taxa_recebimento' => $receitaEsperada > 0 ? round(($receitaRecebida / $receitaEsperada) * 100, 1) : 0,
        'detalhes' => $detalhes
    ];
}

/**
 * Relatório de ocupação
 */
function getRelatorioOcupacao($pdo) {
    // Histórico de ocupação por mês
    $stmt = $pdo->query("
        SELECT 
            DATE_FORMAT(created_at, '%Y-%m') as periodo,
            COUNT(CASE WHEN morador IS NOT NULL AND morador != '' THEN 1 END) as ocupadas,
            COUNT(*) as total
        FROM casas 
        GROUP BY DATE_FORMAT(created_at, '%Y-%m')
        ORDER BY periodo DESC
        LIMIT 12
    ");
    $historico = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Casas com contratos vencendo em 30 dias
    $stmt = $pdo->query("
        SELECT numero, morador, contrato_fim, DATEDIFF(contrato_fim, CURDATE()) as dias_restantes
        FROM casas 
        WHERE contrato_fim IS NOT NULL 
        AND contrato_fim BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)
        ORDER BY contrato_fim
    ");
    $contratosVencendo = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Tempo médio de ocupação
    $stmt = $pdo->query("
        SELECT 
            AVG(DATEDIFF(COALESCE(contrato_fim, CURDATE()), contrato_inicio)) as tempo_medio_dias
        FROM casas 
        WHERE contrato_inicio IS NOT NULL
    ");
    $tempoMedio = $stmt->fetch()['tempo_medio_dias'] ?? 0;
    
    return [
        'historico_ocupacao' => $historico,
        'contratos_vencendo' => $contratosVencendo,
        'tempo_medio_ocupacao' => round($tempoMedio / 30, 1) // em meses
    ];
}

/**
 * Gerenciar upload de arquivos
 */
function handleUpload($method, $pdo) {
    if ($method !== 'POST') {
        throw new Exception('Método não permitido', 405);
    }
    
    if (!isset($_FILES['arquivo'])) {
        throw new Exception('Nenhum arquivo enviado', 400);
    }
    
    $tipo = $_POST['tipo'] ?? '';
    $arquivo = $_FILES['arquivo'];
    
    // Validar tipo de upload
    if (!in_array($tipo, ['contrato', 'comprovante'])) {
        throw new Exception('Tipo de upload inválido', 400);
    }
    
    // Validar arquivo
    $validacao = validateUploadedFile($arquivo);
    if (!$validacao['valid']) {
        throw new Exception($validacao['error'], 400);
    }
    
    // Determinar diretório de destino
    $uploadDir = $tipo === 'contrato' ? UPLOAD_DIR_CONTRATOS : UPLOAD_DIR_COMPROVANTES;
    
    // Gerar nome único do arquivo
    $extension = strtolower(pathinfo($arquivo['name'], PATHINFO_EXTENSION));
    $fileName = generateUniqueFileName($tipo, $extension, $_POST);
    $filePath = $uploadDir . $fileName;
    
    // Fazer upload
    if (!move_uploaded_file($arquivo['tmp_name'], $filePath)) {
        throw new Exception('Erro ao salvar arquivo', 500);
    }
    
    // Otimizar imagem se necessário
    if (in_array($extension, ['jpg', 'jpeg', 'png'])) {
        optimizeImage($filePath, $extension);
    }
    
    logActivity("Upload realizado: $fileName", 'INFO', ['tipo' => $tipo, 'tamanho' => $arquivo['size']]);
    
    echo json_encode([
        'success' => true,
        'filename' => $fileName,
        'url' => $filePath,
        'size' => filesize($filePath),
        'type' => $arquivo['type'],
        'message' => ucfirst($tipo) . ' enviado com sucesso!'
    ]);
}

/**
 * Validar arquivo enviado
 */
function validateUploadedFile($arquivo) {
    // Verificar erros de upload
    if ($arquivo['error'] !== UPLOAD_ERR_OK) {
        $errors = [
            UPLOAD_ERR_INI_SIZE => 'Arquivo muito grande (limite do servidor)',
            UPLOAD_ERR_FORM_SIZE => 'Arquivo muito grande (limite do formulário)',
            UPLOAD_ERR_PARTIAL => 'Upload incompleto',
            UPLOAD_ERR_NO_FILE => 'Nenhum arquivo enviado',
            UPLOAD_ERR_NO_TMP_DIR => 'Diretório temporário não encontrado',
            UPLOAD_ERR_CANT_WRITE => 'Erro ao escrever arquivo',
            UPLOAD_ERR_EXTENSION => 'Upload bloqueado por extensão'
        ];
        
        return [
            'valid' => false,
            'error' => $errors[$arquivo['error']] ?? 'Erro desconhecido no upload'
        ];
    }
    
    // Verificar tamanho
    if ($arquivo['size'] > UPLOAD_MAX_SIZE) {
        return [
            'valid' => false,
            'error' => 'Arquivo muito grande. Máximo permitido: ' . UPLOAD_MAX_SIZE_FORMATTED
        ];
    }
    
    // Verificar tipo de arquivo
    $extension = strtolower(pathinfo($arquivo['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, ALLOWED_FILE_TYPES)) {
        return [
            'valid' => false,
            'error' => 'Tipo de arquivo não permitido. Use apenas: ' . implode(', ', ALLOWED_FILE_TYPES)
        ];
    }
    
    // Verificar MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $arquivo['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = [
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'pdf' => 'application/pdf'
    ];
    
    if (!isset($allowedMimes[$extension]) || $mimeType !== $allowedMimes[$extension]) {
        return [
            'valid' => false,
            'error' => 'Tipo de arquivo não corresponde à extensão'
        ];
    }
    
    return ['valid' => true];
}

/**
 * Gerar nome único para arquivo
 */
function generateUniqueFileName($tipo, $extension, $data = []) {
    $timestamp = time();
    
    if ($tipo === 'contrato') {
        $casaId = $data['casa_id'] ?? 'unknown';
        return "contrato_casa{$casaId}_{$timestamp}.{$extension}";
    } elseif ($tipo === 'comprovante') {
        $casaId = $data['casa_id'] ?? 'unknown';
        $mes = $data['mes'] ?? 'unknown';
        $ano = $data['ano'] ?? 'unknown';
        return "comprovante_casa{$casaId}_{$mes}_{$ano}_{$timestamp}.{$extension}";
    }
    
    return "arquivo_{$timestamp}.{$extension}";
}

/**
 * Otimizar imagem
 */
function optimizeImage($filePath, $extension) {
    try {
        $maxWidth = 1200;
        $maxHeight = 1200;
        $quality = 85;
        
        list($width, $height) = getimagesize($filePath);
        
        // Verificar se precisa redimensionar
        if ($width <= $maxWidth && $height <= $maxHeight) {
            return; // Imagem já está no tamanho adequado
        }
        
        // Calcular novas dimensões
        $ratio = min($maxWidth / $width, $maxHeight / $height);
        $newWidth = intval($width * $ratio);
        $newHeight = intval($height * $ratio);
        
        // Criar nova imagem
        $newImage = imagecreatetruecolor($newWidth, $newHeight);
        
        // Carregar imagem original
        switch ($extension) {
            case 'jpg':
            case 'jpeg':
                $originalImage = imagecreatefromjpeg($filePath);
                break;
            case 'png':
                $originalImage = imagecreatefrompng($filePath);
                imagealphablending($newImage, false);
                imagesavealpha($newImage, true);
                $transparent = imagecolorallocatealpha($newImage, 255, 255, 255, 127);
                imagefill($newImage, 0, 0, $transparent);
                break;
            default:
                return; // Tipo não suportado para otimização
        }
        
        // Redimensionar
        imagecopyresampled($newImage, $originalImage, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
        
        // Salvar imagem otimizada
        switch ($extension) {
            case 'jpg':
            case 'jpeg':
                imagejpeg($newImage, $filePath, $quality);
                break;
            case 'png':
                imagepng($newImage, $filePath, 9);
                break;
        }
        
        // Limpar memória
        imagedestroy($originalImage);
        imagedestroy($newImage);
        
        logActivity("Imagem otimizada: " . basename($filePath), 'INFO');
        
    } catch (Exception $e) {
        error_log("Erro na otimização da imagem: " . $e->getMessage());
    }
}

/**
 * Validar formato de data
 */
function validateDate($date, $format = 'Y-m-d') {
    $d = DateTime::createFromFormat($format, $date);
    return $d && $d->format($format) === $date;
}

/**
 * Função para sanitizar entrada HTML
 */
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Middleware para validação de CSRF (se necessário)
 */
function validateCSRF() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' || $_SERVER['REQUEST_METHOD'] === 'PUT' || $_SERVER['REQUEST_METHOD'] === 'DELETE') {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (empty($token) || !hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
            throw new Exception('Token CSRF inválido', 403);
        }
    }
}

/*
==============================================
 EXEMPLOS DE USO DA API:
==============================================

# Listar todas as casas
GET /api.php/casas

# Buscar casa específica
GET /api.php/casas/1

# Atualizar casa
POST /api.php/casas
{
    "id": 1,
    "morador": "João Silva",
    "telefone": "(11) 99999-9999",
    "contrato_inicio": "2024-01-01",
    "contrato_fim": "2024-12-31",
    "valor_mensal": 1200.00
}

# Remover morador
DELETE /api.php/casas/1

# Listar pagamentos
GET /api.php/pagamentos

# Filtrar pagamentos
GET /api.php/pagamentos?casa_id=1&mes=6&ano=2025

# Criar pagamento
POST /api.php/pagamentos
{
    "casa_id": 1,
    "mes": 6,
    "ano": 2025,
    "valor": 1200.00,
    "data_pagamento": "2025-06-05",
    "status": "pago",
    "comprovante": "comprovante_casa1_6_2025_123456.jpg"
}

# Atualizar pagamento
PUT /api.php/pagamentos/1
{
    "status": "pago",
    "data_pagamento": "2025-06-05"
}

# Excluir pagamento
DELETE /api.php/pagamentos/1

# Criar observação
POST /api.php/observacoes
{
    "casa_id": 1,
    "descricao": "Precisa trocar a fechadura da porta",
    "data": "2025-06-20",
    "status": "pendente"
}

# Relatório geral
GET /api.php/relatorios?tipo=geral

# Relatório financeiro
GET /api.php/relatorios?tipo=financeiro&mes=6&ano=2025

# Upload de arquivo
POST /api.php/upload
Content-Type: multipart/form-data
tipo=comprovante&casa_id=1&mes=6&ano=2025&arquivo=[FILE]

==============================================
 CÓDIGOS DE RESPOSTA HTTP:
==============================================

200 - Sucesso
201 - Criado com sucesso
400 - Dados inválidos
401 - Não autorizado
403 - Acesso negado
404 - Não encontrado
405 - Método não permitido
409 - Conflito (ex: pagamento duplicado)
500 - Erro interno do servidor

==============================================
*/
?>