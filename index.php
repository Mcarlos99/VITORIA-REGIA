// Dados do sistema
        let casas = [];
        let pagamentos = [];
        let observacoes = [];

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

        // Funções de CRUD para Casas
        function editCasa(id) {
            const casa = casas.find(c => c.id === id);
            document.getElementById('casa-id').value = casa.id;
            document.getElementById('casa-numero').value = casa.numero;
            document.getElementById('morador-nome').value = casa.morador || '';
            document.getElementById('morador-telefone').value = casa.telefone || '';
            document.getElementById('contrato-inicio').value = casa.contrato_inicio || '';
            document.getElementById('contrato-fim').value = casa.contrato_fim || '';
            document.getElementById('valor-mensal').value = casa.valor_mensal || '';
            
            document.getElementById('casa-modal-title').textContent = casa.morador ? 'Editar Casa' : 'Nova Casa';
            showModal('casa-modal');
        }

        async function deleteCasa(id) {
            if (confirm('Tem certeza que deseja remover este morador?')) {
                try {
                    await window.api.delete(`casas/${id}`);
                    showAlert('Morador removido com sucesso!', 'success');
                    await loadCasas();
                    await loadPagamentos();
                    await loadObservacoes();
                } catch (error) {
                    showAlert('Erro ao remover morador: ' + error.message, 'danger');
                }
            }
        }

        // Funções de CRUD para Pagamentos
        function editPagamento(id) {
            const pagamento = pagamentos.find(p => p.id === id);
            loadCasasSelect('pagamento');
            
            setTimeout(() => {
                document.getElementById('pagamento-casa').value = pagamento.casa_id;
                document.getElementById('pagamento-mes').value = pagamento.mes;
                document.getElementById('pagamento-ano').value = pagamento.ano;
                document.getElementById('pagamento-valor').value = pagamento.valor;
                document.getElementById('pagamento-data').value = pagamento.data_pagamento || '';
                document.getElementById('pagamento-status').value = pagamento.status;
            }, 100);
            
            showModal('pagamento-modal');
        }

        async function deletePagamento(id) {
            if (confirm('Tem certeza que deseja excluir este pagamento?')) {
                try {
                    await window.api.delete(`pagamentos/${id}`);
                    showAlert('Pagamento excluído com sucesso!', 'success');
                    await loadPagamentos();
                } catch (error) {
                    showAlert('Erro ao excluir pagamento: ' + error.message, 'danger');
                }
            }
        }

        function adicionarPagamentoRapido(casaId) {
            const casa = casas.find(c => c.id === casaId);
            loadCasasSelect('pagamento');
            
            setTimeout(() => {
                document.getElementById('pagamento-casa').value = casaId;
                document.getElementById('pagamento-valor').value = casa.valor_mensal;
                document.getElementById('pagamento-mes').value = new Date().getMonth() + 1;
                document.getElementById('pagamento-ano').value = new Date().getFullYear();
            }, 100);
            
            showModal('pagamento-modal');
        }

        // Funções de CRUD para Observações
        function editObservacao(id) {
            const observacao = observacoes.find(o => o.id === id);
            loadCasasSelect('observacao');
            
            setTimeout(() => {
                document.getElementById('observacao-casa').value = observacao.casa_id;
                document.getElementById('observacao-descricao').value = observacao.descricao;
                document.getElementById('observacao-data').value = observacao.data;
                document.getElementById('observacao-status').value = observacao.status;
            }, 100);
            
            showModal('observacao-modal');
        }

        async function deleteObservacao(id) {
            if (confirm('Tem certeza que deseja excluir esta observação?')) {
                try {
                    await window.api.delete(`observacoes/${id}`);
                    showAlert('Observação excluída com sucesso!', 'success');
                    await loadObservacoes();
                } catch (error) {
                    showAlert('Erro ao excluir observação: ' + error.message, 'danger');
                }
            }
        }

        async function resolverObservacao(id) {
            try {
                const observacao = observacoes.find(o => o.id === id);
                await window.api.put(`observacoes/${id}`, {
                    ...observacao,
                    status: 'resolvida'
                });
                showAlert('Observação marcada como resolvida!', 'success');
                await loadObservacoes();
            } catch (error) {
                showAlert('Erro ao resolver observação: ' + error.message, 'danger');
            }
        }

        // Modais
        function showModal(modalId) {
            document.getElementById(modalId).classList.add('show');
            
            if (modalId === 'pagamento-modal' || modalId === 'observacao-modal') {
                loadCasasSelect(modalId.replace('-modal', ''));
            }
        }

        function hideModal(modalId) {
            document.getElementById(modalId).classList.remove('show');
            const form = document.getElementById(modalId.replace('-modal', '-form'));
            form.reset();
        }

        // Carregar casas no select
        function loadCasasSelect(prefix) {
            const select = document.getElementById(prefix + '-casa');
            select.innerHTML = '<option value="">Selecione a casa...</option>';
            
            casas.forEach(casa => {
                if (casa.morador) {
                    const option = document.createElement('option');
                    option.value = casa.id;
                    option.textContent = `Casa ${casa.numero} - ${casa.morador}`;
                    select.appendChild(option);
                }
            });
        }

        // Event Listeners para formulários
        document.getElementById('casa-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            try {
                const casaData = {
                    id: parseInt(document.getElementById('casa-id').value),
                    morador: document.getElementById('morador-nome').value,
                    telefone: document.getElementById('morador-telefone').value,
                    contrato_inicio: document.getElementById('contrato-inicio').value,
                    contrato_fim: document.getElementById('contrato-fim').value,
                    valor_mensal: parseFloat(document.getElementById('valor-mensal').value)
                };
                
                await window.api.post('casas', casaData);
                hideModal('casa-modal');
                await loadCasas();
                showAlert('Casa salva com sucesso!', 'success');
            } catch (error) {
                showAlert('Erro ao salvar casa: ' + error.message, 'danger');
            }
        });

        document.getElementById('pagamento-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            try {
                const pagamentoData = {
                    casa_id: parseInt(document.getElementById('pagamento-casa').value),
                    mes: parseInt(document.getElementById('pagamento-mes').value),
                    ano: parseInt(document.getElementById('pagamento-ano').value),
                    valor: parseFloat(document.getElementById('pagamento-valor').value),
                    data_pagamento: document.getElementById('pagamento-data').value || null,
                    status: document.getElementById('pagamento-status').value
                };
                
                await window.api.post('pagamentos', pagamentoData);
                hideModal('pagamento-modal');
                await loadPagamentos();
                showAlert('Pagamento salvo com sucesso!', 'success');
            } catch (error) {
                showAlert('Erro ao salvar pagamento: ' + error.message, 'danger');
            }
        });

        document.getElementById('observacao-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            try {
                const observacaoData = {
                    casa_id: parseInt(document.getElementById('observacao-casa').value),
                    descricao: document.getElementById('observacao-descricao').value,
                    data: document.getElementById('observacao-data').value,
                    status: document.getElementById('observacao-status').value
                };
                
                await window.api.post('observacoes', observacaoData);
                hideModal('observacao-modal');
                await loadObservacoes();
                showAlert('Observação salva com sucesso!', 'success');
            } catch (error) {
                showAlert('Erro ao salvar observação: ' + error.message, 'danger');
            }
        });

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
            alertDiv.style.fontWeight = '500';
            
            if (type === 'success') {
                alertDiv.style.background = '#d4edda';
                alertDiv.style.color = '#155724';
                alertDiv.style.borderLeft = '4px solid #28a745';
            } else {
                alertDiv.style.background = '#f8d7da';
                alertDiv.style.color = '#721c24';
                alertDiv.style.borderLeft = '4px solid #dc3545';
            }
            
            document.body.appendChild(alertDiv);
            
            setTimeout(() => {
                alertDiv.remove();
            }, 3000);
        }

        function visualizarComprovante(filename, id) { 
            window.open(`${window.APP_CONFIG<?php
/**
 * Página Principal - Condomínio Vitória Régia
 * Sistema de Gerenciamento de Condomínio
 * 
 * Este é o ponto de entrada principal do sistema.
 * Gerencia roteamento, autenticação e carregamento da interface.
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

// Detectar base URL automaticamente
$protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'];
$path = rtrim(dirname($_SERVER['REQUEST_URI']), '/');
$baseUrl = $protocol . '://' . $host . $path;

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

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
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

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }

        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
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

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border-left: 4px solid #28a745;
        }

        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border-left: 4px solid #dc3545;
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

            .grid {
                grid-template-columns: 1fr;
            }

            .form-row {
                grid-template-columns: 1fr;
            }

            .nav-tab {
                font-size: 14px;
                padding: 12px 15px;
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
                        <!-- Tab Casas -->
                        <div id="casas-tab" class="tab-content active">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                                <h2>Gerenciar Casas</h2>
                                <button class="btn btn-primary" onclick="showModal('casa-modal')">➕ Nova Casa</button>
                            </div>

                            <div class="grid" id="casas-grid">
                                <!-- Casas serão carregadas aqui -->
                            </div>
                        </div>

                        <!-- Tab Pagamentos -->
                        <div id="pagamentos-tab" class="tab-content">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                                <h2>Controle de Pagamentos por Casa</h2>
                                <button class="btn btn-primary" onclick="showModal('pagamento-modal')">➕ Novo Pagamento</button>
                            </div>

                            <div class="grid" id="pagamentos-grid">
                                <!-- Pagamentos por casa serão carregados aqui -->
                            </div>
                        </div>

                        <!-- Tab Observações -->
                        <div id="observacoes-tab" class="tab-content">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                                <h2>Observações e Reparos</h2>
                                <button class="btn btn-primary" onclick="showModal('observacao-modal')">➕ Nova Observação</button>
                            </div>

                            <div id="observacoes-list">
                                <!-- Observações serão carregadas aqui -->
                            </div>
                        </div>

                        <!-- Tab Relatórios -->
                        <div id="relatorios-tab" class="tab-content">
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
                    </div>
                </div>
            </div>

            <!-- Modal Casa -->
            <div id="casa-modal" class="modal">
                <div class="modal-content">
                    <h3 id="casa-modal-title">Nova Casa</h3>
                    <form id="casa-form">
                        <input type="hidden" id="casa-id">
                        
                        <div class="form-group">
                            <label class="form-label">Número da Casa</label>
                            <select class="form-control" id="casa-numero" required>
                                <option value="">Selecione...</option>
                                <option value="1">Casa 1</option>
                                <option value="2">Casa 2</option>
                                <option value="3">Casa 3</option>
                                <option value="4">Casa 4</option>
                                <option value="5">Casa 5</option>
                                <option value="6">Casa 6</option>
                                <option value="7">Casa 7</option>
                                <option value="8">Casa 8</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Nome do Morador</label>
                            <input type="text" class="form-control" id="morador-nome" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Telefone</label>
                            <input type="tel" class="form-control" id="morador-telefone" required>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Início do Contrato</label>
                                <input type="date" class="form-control" id="contrato-inicio" required>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Fim do Contrato</label>
                                <input type="date" class="form-control" id="contrato-fim" required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Valor Mensal (R$)</label>
                            <input type="number" step="0.01" class="form-control" id="valor-mensal" required>
                        </div>

                        <div style="display: flex; gap: 10px; justify-content: flex-end;">
                            <button type="button" class="btn btn-danger" onclick="hideModal('casa-modal')">Cancelar</button>
                            <button type="submit" class="btn btn-success">Salvar</button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Modal Pagamento -->
            <div id="pagamento-modal" class="modal">
                <div class="modal-content">
                    <h3>Novo Pagamento</h3>
                    <form id="pagamento-form">
                        <div class="form-group">
                            <label class="form-label">Casa</label>
                            <select class="form-control" id="pagamento-casa" required>
                                <option value="">Selecione a casa...</option>
                            </select>
                        </div>

                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Mês</label>
                                <select class="form-control" id="pagamento-mes" required>
                                    <option value="1">Janeiro</option>
                                    <option value="2">Fevereiro</option>
                                    <option value="3">Março</option>
                                    <option value="4">Abril</option>
                                    <option value="5">Maio</option>
                                    <option value="6">Junho</option>
                                    <option value="7">Julho</option>
                                    <option value="8">Agosto</option>
                                    <option value="9">Setembro</option>
                                    <option value="10">Outubro</option>
                                    <option value="11">Novembro</option>
                                    <option value="12">Dezembro</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Ano</label>
                                <input type="number" class="form-control" id="pagamento-ano" value="2025" required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Valor (R$)</label>
                            <input type="number" step="0.01" class="form-control" id="pagamento-valor" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Data do Pagamento</label>
                            <input type="date" class="form-control" id="pagamento-data">
                        </div>

                        <div class="form-group">
                            <label class="form-label">Status</label>
                            <select class="form-control" id="pagamento-status" required>
                                <option value="pendente">Pendente</option>
                                <option value="pago">Pago</option>
                                <option value="atrasado">Atrasado</option>
                            </select>
                        </div>

                        <div style="display: flex; gap: 10px; justify-content: flex-end;">
                            <button type="button" class="btn btn-danger" onclick="hideModal('pagamento-modal')">Cancelar</button>
                            <button type="submit" class="btn btn-success">Salvar</button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Modal Observação -->
            <div id="observacao-modal" class="modal">
                <div class="modal-content">
                    <h3>Nova Observação</h3>
                    <form id="observacao-form">
                        <div class="form-group">
                            <label class="form-label">Casa</label>
                            <select class="form-control" id="observacao-casa" required>
                                <option value="">Selecione a casa...</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Descrição</label>
                            <textarea class="form-control" id="observacao-descricao" rows="4" required 
                                      placeholder="Ex: Precisa de manutenção na pia da cozinha"></textarea>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Data</label>
                            <input type="date" class="form-control" id="observacao-data" required>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Status</label>
                            <select class="form-control" id="observacao-status" required>
                                <option value="pendente">Pendente</option>
                                <option value="em_andamento">Em Andamento</option>
                                <option value="resolvida">Resolvida</option>
                            </select>
                        </div>

                        <div style="display: flex; gap: 10px; justify-content: flex-end;">
                            <button type="button" class="btn btn-danger" onclick="hideModal('observacao-modal')">Cancelar</button>
                            <button type="submit" class="btn btn-success">Salvar</button>
                        </div>
                    </form>
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
        // Configurações globais
        window.APP_CONFIG = {
            isLoggedIn: <?php echo $isLoggedIn ? 'true' : 'false'; ?>,
            user: <?php echo $isLoggedIn ? json_encode($userInfo) : 'null'; ?>,
            systemName: <?php echo json_encode(SYSTEM_NAME); ?>,
            apiBase: '<?php echo $baseUrl; ?>/api/',
            uploadBase: '<?php echo $baseUrl; ?>/upload_comprovante.php',
            viewBase: '<?php echo $baseUrl; ?>/view_comprovante.php',
            loginApi: '<?php echo $baseUrl; ?>/login_api.php',
            csrfToken: '<?php echo $_SESSION['csrf_token'] ?? ''; ?>',
            sessionTimeout: <?php echo SESSION_TIMEOUT; ?>,
            debug: <?php echo DEBUG_MODE ? 'true' : 'false'; ?>
        };

        // Dados do sistema
        let casas = [];