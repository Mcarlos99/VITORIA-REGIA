<?php
/**
 * Página Principal - Condomínio Vitória Régia
 * Sistema de Gerenciamento de Condomínio
 * 
 * Este é o ponto de entrada principal do sistema.
 * Gerencia roteamento, autenticação e carregamento da interface.
 * 
 * Funcionalidades:
 * - Verificação de autenticação
 * - Roteamento de requisições
 * - Carregamento da interface principal
 * - Headers de segurança
 * - Redirecionamentos apropriados
 */

// Inicializar sistema
require_once 'config.php';
require_once 'auth.php';

// Configurar headers de segurança
setSecurityHeaders();

// Verificar se é uma requisição de API
$requestUri = $_SERVER['REQUEST_URI'];
$pathInfo = parse_url($requestUri, PHP_URL_PATH);

// Roteamento de APIs
if (strpos($pathInfo, '/api/') !== false) {
    require_once 'api.php';
    exit;
}

if (strpos($pathInfo, '/login_api.php') !== false || $pathInfo === '/login_api') {
    require_once 'login_api.php';
    exit;
}

if (strpos($pathInfo, '/upload_comprovante.php') !== false || $pathInfo === '/upload_comprovante') {
    require_once 'upload_comprovante.php';
    exit;
}

if (strpos($pathInfo, '/view_comprovante.php') !== false || $pathInfo === '/view_comprovante') {
    require_once 'view_comprovante.php';
    exit;
}

// Verificar se usuário está autenticado
$auth = new Auth();
$isLoggedIn = $auth->isLoggedIn();
$userInfo = $isLoggedIn ? $auth->getUserInfo() : null;

// Se não estiver logado, mostrar apenas a tela de login
// Se estiver logado, carregar a aplicação completa
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo SYSTEM_NAME; ?> - Sistema de Gerenciamento</title>
    
    <!-- Meta tags de segurança -->
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <meta name="referrer" content="strict-origin-when-cross-origin">
    
    <!-- Meta tags para PWA -->
    <meta name="theme-color" content="#2C5530">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <meta name="apple-mobile-web-app-title" content="Vitória Régia">
    
    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🏡</text></svg>">
    
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
            padding: 10px;
        }

        /* Loading Screen */
        .loading-screen {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            color: white;
        }

        .loading-spinner {
            width: 50px;
            height: 50px;
            border: 3px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
            margin-bottom: 20px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loading-text {
            font-size: 18px;
            font-weight: 600;
        }

        /* Sistema principal */
        .main-system {
            display: none;
        }

        /* Estilos do sistema (copiados do artifact original) */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
            position: relative;
        }

        .logout-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 20px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            z-index: 1000;
        }

        .logout-btn:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-1px);
        }

        .header {
            background: linear-gradient(135deg, #2C5530 0%, #4A7C59 100%);
            color: white;
            padding: 30px;
            text-align: center;
            position: relative;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }

        .user-info {
            position: absolute;
            top: 20px;
            left: 20px;
            background: rgba(255,255,255,0.2);
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 14px;
            backdrop-filter: blur(10px);
        }

        .nav-tabs {
            display: flex;
            background: #f8f9fa;
            border-bottom: 3px solid #2C5530;
            overflow-x: auto;
        }

        .nav-tab {
            flex: 1;
            padding: 15px 20px;
            text-align: center;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            color: #666;
            transition: all 0.3s ease;
            white-space: nowrap;
            min-width: 120px;
        }

        .nav-tab.active {
            background: #2C5530;
            color: white;
            transform: translateY(-2px);
        }

        .nav-tab:hover {
            background: #4A7C59;
            color: white;
        }

        .content {
            padding: 30px;
            min-height: 500px;
        }

        /* Responsividade */
        @media (max-width: 768px) {
            .container {
                border-radius: 0;
                margin: 0;
                min-height: 100vh;
            }

            .header {
                padding: 20px;
            }

            .header h1 {
                font-size: 1.8em;
            }

            .content {
                padding: 15px;
            }

            .user-info {
                position: static;
                display: inline-block;
                margin-bottom: 10px;
            }

            .logout-btn {
                position: static;
                display: inline-block;
                margin-left: 10px;
            }
        }

        /* Tema escuro (opcional) */
        @media (prefers-color-scheme: dark) {
            .container {
                background: #1a1a1a;
                color: #ffffff;
            }
            
            .nav-tabs {
                background: #2d2d2d;
            }
            
            .nav-tab {
                color: #cccccc;
            }
        }

        /* Estados de conexão */
        .connection-status {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 10px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            z-index: 1000;
            transition: all 0.3s ease;
        }

        .connection-status.online {
            background: #28a745;
            color: white;
        }

        .connection-status.offline {
            background: #dc3545;
            color: white;
        }


        .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.card {
    background: white;
    border-radius: 15px;
    padding: 25px;
    box-shadow: 0 8px 25px rgba(0,0,0,0.1);
    border: 2px solid #f0f0f0;
    transition: all 0.3s ease;
    position: relative;
}

.card:hover {
    transform: translateY(-5px);
    box-shadow: 0 15px 35px rgba(0,0,0,0.15);
    border-color: #2C5530;
}

.card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 2px solid #f0f0f0;
}

.casa-numero {
    background: linear-gradient(135deg, #2C5530, #4A7C59);
    color: white;
    padding: 10px 15px;
    border-radius: 50px;
    font-weight: bold;
    font-size: 18px;
}

.status {
    padding: 5px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
    text-transform: uppercase;
}

.status.ocupada {
    background: #d4edda;
    color: #155724;
}

.status.vazia {
    background: #f8d7da;
    color: #721c24;
}

.info-group {
    margin-bottom: 15px;
}

.info-label {
    font-weight: 600;
    color: #2C5530;
    margin-bottom: 5px;
    display: block;
}

.info-value {
    color: #666;
    font-size: 14px;
    background: #f8f9fa;
    padding: 8px 12px;
    border-radius: 8px;
    border-left: 4px solid #2C5530;
}

.pagamento-item {
    background: #f8f9fa;
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 10px;
    border-left: 4px solid #2C5530;
}

.pagamento-pendente {
    border-left-color: #ffc107;
    background: #fff3cd;
}

.pagamento-pago {
    border-left-color: #28a745;
    background: #d4edda;
}

.pagamento-atrasado {
    border-left-color: #dc3545;
    background: #f8d7da;
}

.observacao-item {
    background: #e3f2fd;
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 10px;
    border-left: 4px solid #2196f3;
}

.observacao-resolvida {
    background: #e8f5e8;
    border-left-color: #4caf50;
}

.btn {
    padding: 12px 20px;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.3s ease;
    text-decoration: none;
    display: inline-block;
    text-align: center;
    margin: 5px;
}

.btn-primary {
    background: linear-gradient(135deg, #2C5530, #4A7C59);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(44, 85, 48, 0.4);
}

.btn-warning {
    background: linear-gradient(135deg, #ffc107, #ffb300);
    color: #212529;
}

.btn-danger {
    background: linear-gradient(135deg, #dc3545, #c82333);
    color: white;
}

.btn-success {
    background: linear-gradient(135deg, #28a745, #20c997);
    color: white;
}
    </style>
</head>
<body>
    <!-- Tela de carregamento -->
    <div id="loading-screen" class="loading-screen">
        <div class="loading-spinner"></div>
        <div class="loading-text">Carregando sistema...</div>
    </div>

    <!-- Sistema principal -->
    <div id="main-system" class="main-system">
        <?php if ($isLoggedIn): ?>
            <!-- Usuário logado - Sistema completo -->
            <div class="container">
                <button class="logout-btn" onclick="logout()">🚪 Sair</button>
                
                <div class="header">
                    <div class="user-info">
                        👤 <?php echo htmlspecialchars($userInfo['nome']); ?>
                    </div>
                    <h1>🏡 Condomínio Vitória Régia</h1>
                    <p>Sistema de Gerenciamento - 8 Casas</p>
                </div>

                <div class="nav-tabs">
                    <button class="nav-tab active" onclick="showTab('casas')">🏠 Casas</button>
                    <button class="nav-tab" onclick="showTab('pagamentos')">💰 Pagamentos</button>
                    <button class="nav-tab" onclick="showTab('observacoes')">📝 Observações</button>
                    <button class="nav-tab" onclick="showTab('relatorios')">📊 Relatórios</button>
                </div>

                <div class="content">
                    <div id="app-content">
                        <!-- Conteúdo será carregado aqui pelo JavaScript -->
                        <div style="text-align: center; padding: 50px; color: #666;">
                            <div style="font-size: 3em; margin-bottom: 20px;">🏗️</div>
                            <h3>Carregando aplicação...</h3>
                            <p>Por favor, aguarde enquanto o sistema é inicializado.</p>
                        </div>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <!-- Usuário não logado - Tela de login -->
            <div id="login-container">
                <!-- Interface de login será carregada aqui -->
            </div>
        <?php endif; ?>
    </div>

    <!-- Indicador de status de conexão -->
    <div id="connection-status" class="connection-status online">🟢 Online</div>

    <script>
// Detectar caminho atual automaticamente
const currentPath = window.location.pathname.replace('/index.php', '').replace(/\/$/, '');

window.APP_CONFIG = {
    isLoggedIn: <?php echo $isLoggedIn ? 'true' : 'false'; ?>,
    user: <?php echo $isLoggedIn ? json_encode($userInfo) : 'null'; ?>,
    systemName: <?php echo json_encode(SYSTEM_NAME); ?>,
    apiBase: currentPath + '/api/',
    uploadBase: currentPath + '/upload_comprovante.php',
    viewBase: currentPath + '/view_comprovante.php',
    loginApi: currentPath + '/login_api.php',
    csrfToken: '<?php echo $_SESSION['csrf_token'] ?? ''; ?>',
    sessionTimeout: <?php echo SESSION_TIMEOUT; ?>,
    debug: <?php echo DEBUG_MODE ? 'true' : 'false'; ?>
};

        // Sistema de gerenciamento de estado
        class AppState {
            constructor() {
                this.data = {
                    casas: [],
                    pagamentos: [],
                    observacoes: [],
                    currentTab: 'casas',
                    loading: false,
                    error: null
                };
                this.listeners = {};
            }

            setState(newState) {
                this.data = { ...this.data, ...newState };
                this.notifyListeners();
            }

            getState() {
                return { ...this.data };
            }

            subscribe(listener) {
                const id = Date.now() + Math.random();
                this.listeners[id] = listener;
                return () => delete this.listeners[id];
            }

            notifyListeners() {
                Object.values(this.listeners).forEach(listener => {
                    try {
                        listener(this.data);
                    } catch (error) {
                        console.error('Erro no listener:', error);
                    }
                });
            }
        }

        // Instância global do estado
        window.appState = new AppState();

        // Sistema de API
        class ApiClient {
            constructor() {
                this.baseUrl = window.APP_CONFIG.apiBase;
            }

            async request(endpoint, options = {}) {
                const url = this.baseUrl + endpoint.replace(/^\//, '');
                
                const config = {
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                        ...options.headers
                    },
                    ...options
                };

                try {
                    const response = await fetch(url, config);
                    
                    // Verificar se sessão expirou
                    if (response.status === 401) {
                        handleSessionExpired();
                        return null;
                    }

                    const data = await response.json();
                    
                    if (!response.ok) {
                        throw new Error(data.error || `HTTP ${response.status}`);
                    }

                    return data;
                } catch (error) {
                    console.error('Erro na API:', error);
                    throw error;
                }
            }

            async get(endpoint) {
                return this.request(endpoint);
            }

            async post(endpoint, data) {
                return this.request(endpoint, {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
            }

            async put(endpoint, data) {
                return this.request(endpoint, {
                    method: 'PUT',
                    body: JSON.stringify(data)
                });
            }

            async delete(endpoint) {
                return this.request(endpoint, {
                    method: 'DELETE'
                });
            }
        }

        // Instância global da API
        window.api = new ApiClient();

        // Função de logout
        async function logout() {
            if (confirm('Tem certeza que deseja sair do sistema?')) {
                try {
                    await fetch(window.APP_CONFIG.loginApi, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'logout' })
                    });
                } catch (error) {
                    console.error('Erro no logout:', error);
                }
                
                // Recarregar página para mostrar tela de login
                window.location.reload();
            }
        }

        // Gerenciar expiração de sessão
        function handleSessionExpired() {
            alert('Sua sessão expirou. Por favor, faça login novamente.');
            window.location.reload();
        }

        // Monitor de conexão
        function setupConnectionMonitor() {
            const statusEl = document.getElementById('connection-status');
            
            function updateStatus() {
                if (navigator.onLine) {
                    statusEl.textContent = '🟢 Online';
                    statusEl.className = 'connection-status online';
                } else {
                    statusEl.textContent = '🔴 Offline';
                    statusEl.className = 'connection-status offline';
                }
            }

            window.addEventListener('online', updateStatus);
            window.addEventListener('offline', updateStatus);
            updateStatus();
        }




// Dados simulados (substituir por dados da API posteriormente)
let casas = [];
let pagamentos = [];
let observacoes = [];

// Navegação entre abas
function showTab(tabName) {
    // Esconder todas as abas
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.style.display = 'none';
    });

    // Remover classe active de todos os botões
    document.querySelectorAll('.nav-tab').forEach(btn => {
        btn.classList.remove('active');
    });

    // Mostrar aba selecionada
    document.getElementById(tabName + '-tab').style.display = 'block';
    event.target.classList.add('active');

    // Recarregar dados se necessário
    if (tabName === 'relatorios') {
        loadRelatorios();
    }
}

// Carregar casas
async function loadCasas() {
    try {
        const response = await window.api.get('casas');
        casas = response.data || [];
        renderCasas();
    } catch (error) {
        console.error('Erro ao carregar casas:', error);
        showAlert('Erro ao carregar casas', 'danger');
    }
}

// Renderizar casas
function renderCasas() {
    const grid = document.getElementById('casas-grid');
    grid.innerHTML = '';

    casas.forEach(casa => {
        const casaHtml = `
            <div class="card">
                <div class="card-header">
                    <div class="casa-numero">Casa ${casa.numero}</div>
                    <div class="status ${casa.morador ? 'ocupada' : 'vazia'}">
                        ${casa.morador ? 'Ocupada' : 'Vazia'}
                    </div>
                </div>
                
                ${casa.morador ? `
                    <div class="info-group">
                        <span class="info-label">👤 Morador</span>
                        <div class="info-value">${casa.morador}</div>
                    </div>
                    
                    <div class="info-group">
                        <span class="info-label">📞 Telefone</span>
                        <div class="info-value">${casa.telefone}</div>
                    </div>
                    
                    <div class="info-group">
                        <span class="info-label">📅 Contrato</span>
                        <div class="info-value">${formatDate(casa.contrato_inicio)} até ${formatDate(casa.contrato_fim)}</div>
                    </div>
                    
                    <div class="info-group">
                        <span class="info-label">💰 Valor Mensal</span>
                        <div class="info-value">R$ ${parseFloat(casa.valor_mensal || 0).toFixed(2)}</div>
                    </div>
                    
                    <div style="margin-top: 20px;">
                        <button class="btn btn-warning" onclick="editCasa(${casa.id})">✏️ Editar</button>
                        <button class="btn btn-danger" onclick="deleteCasa(${casa.id})">🗑️ Remover</button>
                    </div>
                ` : `
                    <div style="text-align: center; padding: 40px 20px; color: #999;">
                        <p>Casa disponível</p>
                        <button class="btn btn-primary" onclick="editCasa(${casa.id})">➕ Adicionar Morador</button>
                    </div>
                `}
            </div>
        `;
        grid.innerHTML += casaHtml;
    });
}

// Carregar pagamentos
async function loadPagamentos() {
    try {
        const response = await window.api.get('pagamentos');
        pagamentos = response.data || [];
        renderPagamentos();
    } catch (error) {
        console.error('Erro ao carregar pagamentos:', error);
        showAlert('Erro ao carregar pagamentos', 'danger');
    }
}

// Renderizar pagamentos por casa
function renderPagamentos() {
    const grid = document.getElementById('pagamentos-grid');
    grid.innerHTML = '';

    // Filtrar apenas casas ocupadas
    const casasOcupadas = casas.filter(casa => casa.morador);

    if (casasOcupadas.length === 0) {
        grid.innerHTML = '<p style="text-align: center; color: #999; padding: 40px; grid-column: 1/-1;">Nenhuma casa ocupada</p>';
        return;
    }

    casasOcupadas.forEach(casa => {
        const pagamentosDaCasa = pagamentos.filter(p => p.casa_id === casa.id);
        const meses = ['Jan', 'Fev', 'Mar', 'Abr', 'Mai', 'Jun', 'Jul', 'Ago', 'Set', 'Out', 'Nov', 'Dez'];
        
        // Calcular estatísticas
        const totalPago = pagamentosDaCasa.filter(p => p.status === 'pago').reduce((total, p) => total + parseFloat(p.valor), 0);
        const pendentes = pagamentosDaCasa.filter(p => p.status === 'pendente').length;
        const atrasados = pagamentosDaCasa.filter(p => p.status === 'atrasado').length;

        let pagamentosHtml = '';
        if (pagamentosDaCasa.length === 0) {
            pagamentosHtml = '<p style="text-align: center; color: #999; padding: 20px;">Nenhum pagamento cadastrado</p>';
        } else {
            // Ordenar pagamentos por ano e mês (mais recentes primeiro)
            pagamentosDaCasa.sort((a, b) => {
                if (a.ano !== b.ano) return b.ano - a.ano;
                return b.mes - a.mes;
            });

            pagamentosDaCasa.forEach(pagamento => {
                const statusClass = pagamento.status === 'pago' ? 'pagamento-pago' : 
                                  pagamento.status === 'atrasado' ? 'pagamento-atrasado' : 'pagamento-pendente';
                
                const comprovanteIcon = pagamento.comprovante ? 
                    (pagamento.comprovante.includes('.pdf') ? '📄' : '🖼️') : '';
                
                const comprovanteLink = pagamento.comprovante ? 
                    `<button class="btn btn-primary" style="padding: 3px 8px; font-size: 11px; margin-left: 10px;" 
                             onclick="visualizarComprovante('${pagamento.comprovante}', ${pagamento.id})">
                        ${comprovanteIcon} Ver Comprovante
                     </button>` : '';
                
                pagamentosHtml += `
                    <div class="pagamento-item ${statusClass}" style="margin-bottom: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <strong>${meses[pagamento.mes - 1]}/${pagamento.ano}</strong>
                                <span class="status ${pagamento.status === 'pago' ? 'ocupada' : 'vazia'}">${pagamento.status.toUpperCase()}</span>
                                ${pagamento.comprovante ? `<span style="font-size: 12px; color: #2C5530;">${comprovanteIcon} Comprovante</span>` : ''}
                            </div>
                            <div style="font-weight: bold;">R$ ${parseFloat(pagamento.valor).toFixed(2)}</div>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 14px; color: #666;">
                            <div>
                                ${pagamento.data_pagamento ? 'Pago em: ' + formatDate(pagamento.data_pagamento) : 'Não pago'}
                                ${comprovanteLink}
                            </div>
                            <div style="display: flex; gap: 5px;">
                                <button class="btn btn-warning" style="padding: 5px 10px; font-size: 12px;" onclick="editPagamento(${pagamento.id})">✏️</button>
                                <button class="btn btn-danger" style="padding: 5px 10px; font-size: 12px;" onclick="deletePagamento(${pagamento.id})">🗑️</button>
                            </div>
                        </div>
                    </div>
                `;
            });
        }

        const casaHtml = `
            <div class="card">
                <div class="card-header">
                    <div class="casa-numero">Casa ${casa.numero}</div>
                    <div style="text-align: right;">
                        <div style="font-size: 14px; color: #666;">
                            💰 R$ ${parseFloat(casa.valor_mensal || 0).toFixed(2)}/mês
                        </div>
                    </div>
                </div>
                
                <div class="info-group">
                    <span class="info-label">👤 Morador</span>
                    <div class="info-value">${casa.morador}</div>
                </div>

                <!-- Resumo Financeiro -->
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0;">
                    <h4 style="margin-bottom: 10px; color: #2C5530;">📊 Resumo Financeiro</h4>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 14px;">
                        <div><strong>Total Recebido:</strong> R$ ${totalPago.toFixed(2)}</div>
                        <div><strong>Pendentes:</strong> ${pendentes}</div>
                        <div><strong>Atrasados:</strong> ${atrasados}</div>
                        <div><strong>Total Pagamentos:</strong> ${pagamentosDaCasa.length}</div>
                    </div>
                </div>

                <!-- Histórico de Pagamentos -->
                <div style="margin-top: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                        <h4 style="color: #2C5530;">💳 Histórico de Pagamentos</h4>
                        <button class="btn btn-primary" style="padding: 5px 12px; font-size: 12px;" 
                                onclick="adicionarPagamentoRapido(${casa.id})">➕ Adicionar</button>
                    </div>
                    <div style="max-height: 300px; overflow-y: auto;">
                        ${pagamentosHtml}
                    </div>
                </div>
            </div>
        `;
        grid.innerHTML += casaHtml;
    });
}

// Carregar observações
async function loadObservacoes() {
    try {
        const response = await window.api.get('observacoes');
        observacoes = response.data || [];
        renderObservacoes();
    } catch (error) {
        console.error('Erro ao carregar observações:', error);
        showAlert('Erro ao carregar observações', 'danger');
    }
}

// Renderizar observações
function renderObservacoes() {
    const list = document.getElementById('observacoes-list');
    list.innerHTML = '';

    if (observacoes.length === 0) {
        list.innerHTML = '<p style="text-align: center; color: #999; padding: 40px;">Nenhuma observação cadastrada</p>';
        return;
    }

    observacoes.forEach(observacao => {
        const casa = casas.find(c => c.id === observacao.casa_id);
        
        const observacaoHtml = `
            <div class="observacao-item ${observacao.status === 'resolvida' ? 'observacao-resolvida' : ''}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <strong>Casa ${casa?.numero} - ${casa?.morador}</strong>
                    <span class="status ${observacao.status === 'resolvida' ? 'ocupada' : 'vazia'}">${observacao.status.toUpperCase()}</span>
                </div>
                <div style="margin-bottom: 10px;">
                    <strong>Data:</strong> ${formatDate(observacao.data)}
                </div>
                <div style="background: white; padding: 10px; border-radius: 5px; margin-bottom: 15px;">
                    ${observacao.descricao}
                </div>
                <div>
                    <button class="btn btn-warning" onclick="editObservacao(${observacao.id})">✏️ Editar</button>
                    <button class="btn btn-danger" onclick="deleteObservacao(${observacao.id})">🗑️ Excluir</button>
                    ${observacao.status !== 'resolvida' ? `<button class="btn btn-success" onclick="resolverObservacao(${observacao.id})">✅ Resolver</button>` : ''}
                </div>
            </div>
        `;
        list.innerHTML += observacaoHtml;
    });
}

// Carregar relatórios
function loadRelatorios() {
    loadResumoGeral();
    loadSituacaoFinanceira();
}

function loadResumoGeral() {
    const resumo = document.getElementById('resumo-geral');
    const casasOcupadas = casas.filter(c => c.morador).length;
    const casasVazias = 8 - casasOcupadas;
    const observacoesPendentes = observacoes.filter(o => o.status !== 'resolvida').length;

    resumo.innerHTML = `
        <div style="display: grid; gap: 15px;">
            <div class="info-group">
                <span class="info-label">🏠 Casas Ocupadas</span>
                <div class="info-value">${casasOcupadas} de 8</div>
            </div>
            <div class="info-group">
                <span class="info-label">🏘️ Casas Vazias</span>
                <div class="info-value">${casasVazias}</div>
            </div>
            <div class="info-group">
                <span class="info-label">⚠️ Observações Pendentes</span>
                <div class="info-value">${observacoesPendentes}</div>
            </div>
            <div class="info-group">
                <span class="info-label">📊 Taxa de Ocupação</span>
                <div class="info-value">${((casasOcupadas / 8) * 100).toFixed(1)}%</div>
            </div>
        </div>
    `;
}

function loadSituacaoFinanceira() {
    const situacao = document.getElementById('situacao-financeira');
    const mesAtual = new Date().getMonth() + 1;
    const anoAtual = new Date().getFullYear();
    
    const pagamentosDoMes = pagamentos.filter(p => p.mes === mesAtual && p.ano === anoAtual);
    const receitaEsperada = casas.filter(c => c.morador).reduce((total, casa) => total + parseFloat(casa.valor_mensal || 0), 0);
    const receitaRecebida = pagamentosDoMes.filter(p => p.status === 'pago').reduce((total, p) => total + parseFloat(p.valor), 0);
    const pendentes = pagamentosDoMes.filter(p => p.status === 'pendente').length;
    const atrasados = pagamentosDoMes.filter(p => p.status === 'atrasado').length;

    situacao.innerHTML = `
        <div style="display: grid; gap: 15px;">
            <div class="info-group">
                <span class="info-label">💰 Receita Esperada (Mês)</span>
                <div class="info-value">R$ ${receitaEsperada.toFixed(2)}</div>
            </div>
            <div class="info-group">
                <span class="info-label">✅ Receita Recebida</span>
                <div class="info-value">R$ ${receitaRecebida.toFixed(2)}</div>
            </div>
            <div class="info-group">
                <span class="info-label">⏳ Pagamentos Pendentes</span>
                <div class="info-value">${pendentes}</div>
            </div>
            <div class="info-group">
                <span class="info-label">🔴 Pagamentos Atrasados</span>
                <div class="info-value">${atrasados}</div>
            </div>
            <div class="info-group">
                <span class="info-label">📈 Taxa de Recebimento</span>
                <div class="info-value">${receitaEsperada > 0 ? ((receitaRecebida / receitaEsperada) * 100).toFixed(1) : 0}%</div>
            </div>
        </div>
    `;
}

// Funções auxiliares
function formatDate(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR');
}

function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    alertDiv.style.position = 'fixed';
    alertDiv.style.top = '20px';
    alertDiv.style.right = '20px';
    alertDiv.style.zIndex = '9999';
    alertDiv.style.minWidth = '300px';
    alertDiv.style.padding = '15px';
    alertDiv.style.borderRadius = '8px';
    alertDiv.style.color = type === 'success' ? '#155724' : '#721c24';
    alertDiv.style.backgroundColor = type === 'success' ? '#d4edda' : '#f8d7da';
    alertDiv.style.border = `1px solid ${type === 'success' ? '#c3e6cb' : '#f5c6cb'}`;
    
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 3000);
}

// Placeholder functions (implementar conforme necessário)
function showModal(modalId) { console.log('Abrir modal:', modalId); }
function editCasa(id) { console.log('Editar casa:', id); }
function deleteCasa(id) { console.log('Deletar casa:', id); }
function editPagamento(id) { console.log('Editar pagamento:', id); }
function deletePagamento(id) { console.log('Deletar pagamento:', id); }
function adicionarPagamentoRapido(casaId) { console.log('Adicionar pagamento para casa:', casaId); }
function editObservacao(id) { console.log('Editar observação:', id); }
function deleteObservacao(id) { console.log('Deletar observação:', id); }
function resolverObservacao(id) { console.log('Resolver observação:', id); }
function visualizarComprovante(filename, id) { 
    window.open(`${window.APP_CONFIG.viewBase}?file=${encodeURIComponent(filename)}`, '_blank');
}






        // Inicialização da aplicação
        async function initializeApp() {
            try {
                // Configurar monitor de conexão
                setupConnectionMonitor();

                if (window.APP_CONFIG.isLoggedIn) {
                    // Carregar aplicação principal
                    await loadMainApplication();
                } else {
                    // Carregar interface de login
                    await loadLoginInterface();
                }

                // Esconder tela de carregamento
                document.getElementById('loading-screen').style.display = 'none';
                document.getElementById('main-system').style.display = 'block';

            } catch (error) {
                console.error('Erro na inicialização:', error);
                document.getElementById('loading-screen').innerHTML = `
                    <div style="text-align: center; color: white;">
                        <div style="font-size: 3em; margin-bottom: 20px;">❌</div>
                        <h3>Erro na inicialização</h3>
                        <p>${error.message}</p>
                        <button onclick="window.location.reload()" 
                                style="margin-top: 20px; padding: 10px 20px; background: white; color: #333; border: none; border-radius: 5px; cursor: pointer;">
                            Tentar novamente
                        </button>
                    </div>
                `;
            }
        }

// Carregar aplicação principal
async function loadMainApplication() {
    // Inserir todo o HTML das abas
    document.getElementById('app-content').innerHTML = `
        <!-- Tab Casas -->
        <div id="casas-tab" class="tab-content">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                <h2>Gerenciar Casas</h2>
                <button class="btn btn-primary" onclick="showModal('casa-modal')">➕ Nova Casa</button>
            </div>

            <div class="grid" id="casas-grid">
                <!-- Casas serão carregadas aqui -->
            </div>
        </div>

        <!-- Tab Pagamentos -->
        <div id="pagamentos-tab" class="tab-content" style="display: none;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                <h2>Controle de Pagamentos por Casa</h2>
                <button class="btn btn-primary" onclick="showModal('pagamento-modal')">➕ Novo Pagamento</button>
            </div>

            <div class="grid" id="pagamentos-grid">
                <!-- Pagamentos por casa serão carregados aqui -->
            </div>
        </div>

        <!-- Tab Observações -->
        <div id="observacoes-tab" class="tab-content" style="display: none;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                <h2>Observações e Reparos</h2>
                <button class="btn btn-primary" onclick="showModal('observacao-modal')">➕ Nova Observação</button>
            </div>

            <div id="observacoes-list">
                <!-- Observações serão carregadas aqui -->
            </div>
        </div>

        <!-- Tab Relatórios -->
        <div id="relatorios-tab" class="tab-content" style="display: none;">
            <h2>Relatórios Gerenciais</h2>
            
            <div class="grid">
                <div class="card">
                    <h3>📊 Resumo Geral</h3>
                    <div id="resumo-geral">
                        <!-- Resumo será carregado aqui -->
                    </div>
                </div>
                
                <div class="card">
                    <h3>💰 Situação Financeira</h3>
                    <div id="situacao-financeira">
                        <!-- Situação financeira será carregada aqui -->
                    </div>
                </div>
            </div>
        </div>
    `;

    // Carregar dados iniciais via API
    await loadCasas();
    await loadPagamentos();
    await loadObservacoes();
    loadRelatorios();
    
    console.log('Aplicação principal carregada para:', window.APP_CONFIG.user);
}

        // Carregar interface de login
        async function loadLoginInterface() {
            document.getElementById('login-container').innerHTML = `
                <div style="display: flex; align-items: center; justify-content: center; min-height: 100vh;">
                    <div style="background: white; padding: 40px; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); max-width: 400px; width: 100%; text-align: center;">
                        <div style="font-size: 4em; margin-bottom: 20px;">🏡</div>
                        <h2 style="color: #2C5530; margin-bottom: 10px;">${window.APP_CONFIG.systemName}</h2>
                        <p style="color: #666; margin-bottom: 30px;">Sistema de Gerenciamento</p>
                        
                        <div id="login-error" style="background: #f8d7da; color: #721c24; padding: 12px; border-radius: 8px; margin-bottom: 20px; display: none;">
                            Usuário ou senha incorretos!
                        </div>
                        
                        <form id="login-form">
                            <input type="text" id="username" placeholder="Usuário" required
                                   style="width: 100%; padding: 15px; margin-bottom: 15px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 16px;">
                            <input type="password" id="password" placeholder="Senha" required
                                   style="width: 100%; padding: 15px; margin-bottom: 20px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 16px;">
                            <button type="submit" id="login-btn"
                                    style="width: 100%; padding: 15px; background: linear-gradient(135deg, #2C5530, #4A7C59); color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer;">
                                🚀 Entrar no Sistema
                            </button>
                        </form>
                        
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; font-size: 14px; color: #666;">
                            <p><strong>Credenciais padrão:</strong></p>
                            <p>Usuário: <code>admin</code></p>
                            <p>Senha: <code>vitoria2025</code></p>
                        </div>
                    </div>
                </div>
            `;

            // Configurar formulário de login
            document.getElementById('login-form').addEventListener('submit', handleLogin);
        }

        // Processar login
        async function handleLogin(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('login-error');
            const loginBtn = document.getElementById('login-btn');
            
            loginBtn.disabled = true;
            loginBtn.textContent = '🔄 Verificando...';
            errorDiv.style.display = 'none';
            
            try {
                const response = await fetch(window.APP_CONFIG.loginApi, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        action: 'login',
                        username: username,
                        password: password
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Login bem-sucedido - recarregar página
                    window.location.reload();
                } else {
                    // Erro no login
                    errorDiv.textContent = result.error;
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'Erro de conexão. Tente novamente.';
                errorDiv.style.display = 'block';
            }
            
            loginBtn.disabled = false;
            loginBtn.textContent = '🚀 Entrar no Sistema';
        }

        // Navegação entre abas (placeholder)
        function showTab(tabName) {
            console.log('Mudando para aba:', tabName);
            // Implementar navegação entre abas
        }

        // Inicializar quando DOM estiver pronto
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializeApp);
        } else {
            initializeApp();
        }

        // Log de inicialização
        console.log('Sistema Condomínio Vitória Régia v<?php echo SYSTEM_VERSION; ?>');
        console.log('Usuário logado:', window.APP_CONFIG.isLoggedIn);
        console.log('Debug mode:', window.APP_CONFIG.debug);
    </script>
</body>
</html>

<?php
/**
 * Função para configurar headers de segurança
 */
function setSecurityHeaders() {
    // Prevenir clickjacking
    header('X-Frame-Options: DENY');
    
    // Prevenir MIME type sniffing
    header('X-Content-Type-Options: nosniff');
    
    // Ativar proteção XSS
    header('X-XSS-Protection: 1; mode=block');
    
    // Política de referência
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // Content Security Policy
    $csp = "default-src 'self'; " .
           "script-src 'self' 'unsafe-inline'; " .
           "style-src 'self' 'unsafe-inline'; " .
           "img-src 'self' data: blob:; " .
           "font-src 'self'; " .
           "connect-src 'self'; " .
           "media-src 'self'; " .
           "object-src 'none'; " .
           "base-uri 'self'; " .
           "form-action 'self';";
    
    header("Content-Security-Policy: $csp");
    
    // HSTS para HTTPS (ativar em produção)
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
}

/*
==============================================
 INTEGRAÇÃO COM O SISTEMA COMPLETO:
==============================================

Para integrar completamente o sistema:

1. Copie todo o JavaScript do artifact HTML original
2. Cole no método loadMainApplication()
3. Substitua as funções de dados simulados por chamadas à API
4. Configure as rotas apropriadas

Exemplo de integração:

async function loadMainApplication() {
    // Carregar dados iniciais
    const casas = await window.api.get('casas');
    const pagamentos = await window.api.get('pagamentos');
    const observacoes = await window.api.get('observacoes');
    
    // Atualizar estado
    window.appState.setState({
        casas: casas.data,
        pagamentos: pagamentos.data,
        observacoes: observacoes.data
    });
    
    // Carregar interface completa
    document.getElementById('app-content').innerHTML = `
        <!-- HTML das abas do sistema -->
    `;
    
    // Inicializar funcionalidades
    initializeTabs();
    initializeModals();
    loadCasas();
}

==============================================
*/
?>