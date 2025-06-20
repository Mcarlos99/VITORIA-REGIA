<?php
/**
 * Sistema de Upload de Comprovantes - Condomínio Vitória Régia
 * 
 * Este arquivo gerencia o upload seguro de comprovantes de pagamento:
 * - Validação rigorosa de arquivos
 * - Otimização automática de imagens
 * - Nomenclatura padronizada
 * - Proteção contra uploads maliciosos
 * - Logs detalhados de operações
 * 
 * Formatos aceitos: JPG, PNG, PDF
 * Tamanho máximo: 5MB
 * 
 * Uso:
 * POST /upload_comprovante.php
 * Content-Type: multipart/form-data
 * 
 * Campos obrigatórios:
 * - comprovante (arquivo)
 * - casa_id (número da casa)
 * - mes (mês do pagamento)
 * - ano (ano do pagamento)
 */

require_once 'config.php';
require_once 'auth.php';

// Verificar autenticação
$auth = authMiddleware();

// Configurar headers
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

// Tratar requisições OPTIONS (preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Permitir apenas método POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => 'Método não permitido. Use POST com multipart/form-data.',
        'code' => 405
    ]);
    exit;
}

// Log da requisição
$userInfo = getCurrentUser();
logActivity("Upload Request", 'INFO', [
    'user' => $userInfo['username'] ?? 'unknown',
    'ip' => $_SERVER['REMOTE_ADDR'],
    'files' => array_keys($_FILES),
    'post_data' => array_keys($_POST)
]);

try {
    // Verificar se arquivo foi enviado
    if (!isset($_FILES['comprovante'])) {
        throw new Exception('Nenhum arquivo de comprovante foi enviado.', 400);
    }
    
    // Verificar dados do formulário
    $requiredFields = ['casa_id', 'mes', 'ano'];
    foreach ($requiredFields as $field) {
        if (!isset($_POST[$field]) || $_POST[$field] === '') {
            throw new Exception("Campo '$field' é obrigatório.", 400);
        }
    }
    
    // Validar dados do formulário
    $casaId = validateCasaId($_POST['casa_id']);
    $mes = validateMes($_POST['mes']);
    $ano = validateAno($_POST['ano']);
    
    // Processar upload
    $uploadResult = processUpload($_FILES['comprovante'], $casaId, $mes, $ano);
    
    // Retornar sucesso
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => 'Comprovante enviado com sucesso!',
        'data' => $uploadResult
    ]);
    
} catch (Exception $e) {
    $code = $e->getCode() ?: 500;
    http_response_code($code);
    
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'code' => $code
    ]);
    
    // Log do erro
    error_log("Upload Error: " . $e->getMessage());
    logActivity("Upload Error: " . $e->getMessage(), 'ERROR', [
        'user' => $userInfo['username'] ?? 'unknown',
        'files' => $_FILES,
        'post' => $_POST
    ]);
}

/**
 * Validar ID da casa
 */
function validateCasaId($casaId) {
    if (!is_numeric($casaId) || $casaId < 1 || $casaId > 8) {
        throw new Exception('ID da casa deve ser um número entre 1 e 8.', 400);
    }
    
    // Verificar se casa existe no banco
    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT numero, morador FROM casas WHERE id = ?");
    $stmt->execute([$casaId]);
    $casa = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$casa) {
        throw new Exception('Casa não encontrada.', 404);
    }
    
    if (empty($casa['morador'])) {
        throw new Exception('Esta casa não possui morador cadastrado.', 400);
    }
    
    return (int) $casaId;
}

/**
 * Validar mês
 */
function validateMes($mes) {
    if (!is_numeric($mes) || $mes < 1 || $mes > 12) {
        throw new Exception('Mês deve ser um número entre 1 e 12.', 400);
    }
    
    return (int) $mes;
}

/**
 * Validar ano
 */
function validateAno($ano) {
    $currentYear = date('Y');
    if (!is_numeric($ano) || $ano < 2020 || $ano > ($currentYear + 1)) {
        throw new Exception("Ano deve ser entre 2020 e " . ($currentYear + 1) . ".", 400);
    }
    
    return (int) $ano;
}

/**
 * Processar upload do arquivo
 */
function processUpload($file, $casaId, $mes, $ano) {
    // Validar arquivo
    $validation = validateUploadedFile($file);
    if (!$validation['valid']) {
        throw new Exception($validation['error'], 400);
    }
    
    // Verificar se já existe comprovante para este período
    checkExistingComprovante($casaId, $mes, $ano);
    
    // Gerar nome único do arquivo
    $fileInfo = pathinfo($file['name']);
    $extension = strtolower($fileInfo['extension']);
    $fileName = generateFileName($casaId, $mes, $ano, $extension);
    
    // Criar diretório se não existir
    createUploadDirectory();
    
    // Caminho completo do arquivo
    $filePath = UPLOAD_DIR_COMPROVANTES . $fileName;
    
    // Fazer upload
    if (!move_uploaded_file($file['tmp_name'], $filePath)) {
        throw new Exception('Erro ao salvar arquivo no servidor.', 500);
    }
    
    // Aplicar permissões corretas
    chmod($filePath, 0644);
    
    // Otimizar arquivo se for imagem
    if (in_array($extension, ['jpg', 'jpeg', 'png'])) {
        optimizeImage($filePath, $extension);
    }
    
    // Obter informações finais do arquivo
    $fileInfo = getFileInfo($filePath, $fileName);
    
    // Log da operação
    logActivity("Comprovante uploaded: $fileName", 'INFO', [
        'casa_id' => $casaId,
        'mes' => $mes,
        'ano' => $ano,
        'original_name' => $file['name'],
        'file_size' => $fileInfo['size'],
        'file_type' => $fileInfo['type']
    ]);
    
    return $fileInfo;
}

/**
 * Validar arquivo enviado
 */
function validateUploadedFile($file) {
    // Verificar erros de upload
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors = [
            UPLOAD_ERR_INI_SIZE => 'Arquivo muito grande (limite do servidor: ' . ini_get('upload_max_filesize') . ')',
            UPLOAD_ERR_FORM_SIZE => 'Arquivo muito grande (limite do formulário)',
            UPLOAD_ERR_PARTIAL => 'Upload foi interrompido. Tente novamente.',
            UPLOAD_ERR_NO_FILE => 'Nenhum arquivo foi selecionado',
            UPLOAD_ERR_NO_TMP_DIR => 'Diretório temporário não encontrado no servidor',
            UPLOAD_ERR_CANT_WRITE => 'Erro de permissão ao escrever arquivo',
            UPLOAD_ERR_EXTENSION => 'Upload bloqueado por extensão de arquivo'
        ];
        
        return [
            'valid' => false,
            'error' => $errors[$file['error']] ?? 'Erro desconhecido no upload (código: ' . $file['error'] . ')'
        ];
    }
    
    // Verificar se arquivo foi realmente enviado
    if (!is_uploaded_file($file['tmp_name'])) {
        return [
            'valid' => false,
            'error' => 'Arquivo não foi enviado corretamente.'
        ];
    }
    
    // Verificar tamanho
    if ($file['size'] <= 0) {
        return [
            'valid' => false,
            'error' => 'Arquivo está vazio.'
        ];
    }
    
    if ($file['size'] > UPLOAD_MAX_SIZE) {
        return [
            'valid' => false,
            'error' => 'Arquivo muito grande. Tamanho máximo: ' . formatBytes(UPLOAD_MAX_SIZE)
        ];
    }
    
    // Verificar nome do arquivo
    if (empty($file['name']) || strlen($file['name']) > 255) {
        return [
            'valid' => false,
            'error' => 'Nome do arquivo inválido.'
        ];
    }
    
    // Verificar extensão
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, ALLOWED_FILE_TYPES)) {
        return [
            'valid' => false,
            'error' => 'Tipo de arquivo não permitido. Formatos aceitos: ' . implode(', ', array_map('strtoupper', ALLOWED_FILE_TYPES))
        ];
    }
    
    // Verificar MIME type
    $mimeValidation = validateMimeType($file['tmp_name'], $extension);
    if (!$mimeValidation['valid']) {
        return $mimeValidation;
    }
    
    // Verificar se não é um arquivo executável disfarçado
    if (isExecutableFile($file['tmp_name'])) {
        return [
            'valid' => false,
            'error' => 'Arquivo suspeito detectado. Upload negado.'
        ];
    }
    
    return ['valid' => true];
}

/**
 * Validar MIME type
 */
function validateMimeType($tmpName, $extension) {
    if (!function_exists('finfo_open')) {
        // Se finfo não estiver disponível, pular validação MIME
        return ['valid' => true];
    }
    
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $tmpName);
    finfo_close($finfo);
    
    $allowedMimes = [
        'jpg' => ['image/jpeg'],
        'jpeg' => ['image/jpeg'],
        'png' => ['image/png'],
        'pdf' => ['application/pdf']
    ];
    
    if (!isset($allowedMimes[$extension])) {
        return [
            'valid' => false,
            'error' => 'Extensão de arquivo não suportada.'
        ];
    }
    
    if (!in_array($mimeType, $allowedMimes[$extension])) {
        return [
            'valid' => false,
            'error' => 'Tipo de arquivo não corresponde à extensão. Detectado: ' . $mimeType
        ];
    }
    
    return ['valid' => true];
}

/**
 * Verificar se arquivo é executável
 */
function isExecutableFile($tmpName) {
    // Ler primeiros bytes do arquivo
    $handle = fopen($tmpName, 'rb');
    if (!$handle) {
        return false;
    }
    
    $header = fread($handle, 512);
    fclose($handle);
    
    // Assinaturas de arquivos executáveis
    $executableSignatures = [
        'MZ',           // Windows PE
        "\x7fELF",      // Linux ELF
        "\xCA\xFE\xBA\xBE", // Java class
        "#!/",          // Script com shebang
        "<?php",        // PHP script
        "<script",      // JavaScript/HTML
    ];
    
    foreach ($executableSignatures as $signature) {
        if (strpos($header, $signature) === 0 || strpos($header, $signature) !== false) {
            return true;
        }
    }
    
    return false;
}

/**
 * Verificar se já existe comprovante para este período
 */
function checkExistingComprovante($casaId, $mes, $ano) {
    $pdo = getDB();
    $stmt = $pdo->prepare("
        SELECT id, comprovante 
        FROM pagamentos 
        WHERE casa_id = ? AND mes = ? AND ano = ? AND comprovante IS NOT NULL
    ");
    $stmt->execute([$casaId, $mes, $ano]);
    $existing = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($existing) {
        // Verificar se arquivo ainda existe
        $existingPath = UPLOAD_DIR_COMPROVANTES . $existing['comprovante'];
        if (file_exists($existingPath)) {
            throw new Exception(
                'Já existe um comprovante para esta casa neste período. ' .
                'Exclua o pagamento existente antes de enviar um novo comprovante.',
                409
            );
        } else {
            // Arquivo não existe mais, limpar referência no banco
            $updateStmt = $pdo->prepare("UPDATE pagamentos SET comprovante = NULL WHERE id = ?");
            $updateStmt->execute([$existing['id']]);
        }
    }
}

/**
 * Gerar nome único do arquivo
 */
function generateFileName($casaId, $mes, $ano, $extension) {
    $timestamp = time();
    $random = substr(str_shuffle('0123456789abcdefghijklmnopqrstuvwxyz'), 0, 8);
    
    return sprintf(
        'comprovante_casa%02d_%02d_%04d_%d_%s.%s',
        $casaId,
        $mes,
        $ano,
        $timestamp,
        $random,
        $extension
    );
}

/**
 * Criar diretório de upload se não existir
 */
function createUploadDirectory() {
    if (!is_dir(UPLOAD_DIR_COMPROVANTES)) {
        if (!mkdir(UPLOAD_DIR_COMPROVANTES, 0755, true)) {
            throw new Exception('Erro ao criar diretório de upload.', 500);
        }
        
        // Criar arquivo .htaccess para proteção
        createHtaccessProtection(UPLOAD_DIR_COMPROVANTES);
    }
    
    // Verificar permissões de escrita
    if (!is_writable(UPLOAD_DIR_COMPROVANTES)) {
        throw new Exception('Diretório de upload não tem permissão de escrita.', 500);
    }
}

/**
 * Criar proteção .htaccess
 */
function createHtaccessProtection($directory) {
    $htaccessContent = '# Proteção de segurança para uploads - Condomínio Vitória Régia
# Gerado automaticamente em ' . date('Y-m-d H:i:s') . '

# Desabilitar execução de scripts PHP
php_flag engine off
AddHandler cgi-script .php .phtml .php3 .php4 .php5 .pl .py .jsp .asp .sh .cgi
Options -ExecCGI -Indexes

# Permitir apenas visualização de arquivos específicos
<Files ~ "\.(jpg|jpeg|png|pdf)$">
    Order allow,deny
    Allow from all
</Files>

# Bloquear acesso a todos os outros tipos de arquivo
<Files ~ "\.">
    Order allow,deny
    Deny from all
</Files>

# Bloquear acesso direto a este arquivo
<Files ".htaccess">
    Order allow,deny
    Deny from all
</Files>

# Headers de segurança
<IfModule mod_headers.c>
    Header set X-Content-Type-Options nosniff
    Header set X-Frame-Options DENY
    Header set X-XSS-Protection "1; mode=block"
</IfModule>

# Configurar tipos MIME corretos
<IfModule mod_mime.c>
    AddType image/jpeg .jpg .jpeg
    AddType image/png .png
    AddType application/pdf .pdf
</IfModule>
';
    
    file_put_contents($directory . '.htaccess', $htaccessContent);
}

/**
 * Otimizar imagem
 */
function optimizeImage($filePath, $extension) {
    try {
        // Configurações de otimização
        $maxWidth = 1920;      // Largura máxima
        $maxHeight = 1920;     // Altura máxima
        $jpegQuality = 85;     // Qualidade JPEG (0-100)
        $pngCompression = 6;   // Compressão PNG (0-9)
        
        // Obter dimensões originais
        $imageInfo = getimagesize($filePath);
        if (!$imageInfo) {
            throw new Exception('Não foi possível ler informações da imagem');
        }
        
        $originalWidth = $imageInfo[0];
        $originalHeight = $imageInfo[1];
        $originalSize = filesize($filePath);
        
        // Verificar se precisa redimensionar
        $needsResize = $originalWidth > $maxWidth || $originalHeight > $maxHeight;
        
        if (!$needsResize && $originalSize <= (2 * 1024 * 1024)) {
            // Imagem já está em tamanho adequado e menor que 2MB
            return;
        }
        
        // Calcular novas dimensões mantendo proporção
        if ($needsResize) {
            $ratio = min($maxWidth / $originalWidth, $maxHeight / $originalHeight);
            $newWidth = intval($originalWidth * $ratio);
            $newHeight = intval($originalHeight * $ratio);
        } else {
            $newWidth = $originalWidth;
            $newHeight = $originalHeight;
        }
        
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
                // Preservar transparência
                imagealphablending($newImage, false);
                imagesavealpha($newImage, true);
                $transparent = imagecolorallocatealpha($newImage, 255, 255, 255, 127);
                imagefill($newImage, 0, 0, $transparent);
                break;
            default:
                throw new Exception('Formato de imagem não suportado para otimização');
        }
        
        if (!$originalImage) {
            throw new Exception('Erro ao carregar imagem original');
        }
        
        // Redimensionar com qualidade alta
        if (!imagecopyresampled(
            $newImage, $originalImage,
            0, 0, 0, 0,
            $newWidth, $newHeight,
            $originalWidth, $originalHeight
        )) {
            throw new Exception('Erro ao redimensionar imagem');
        }
        
        // Salvar imagem otimizada
        $success = false;
        switch ($extension) {
            case 'jpg':
            case 'jpeg':
                $success = imagejpeg($newImage, $filePath, $jpegQuality);
                break;
            case 'png':
                $success = imagepng($newImage, $filePath, $pngCompression);
                break;
        }
        
        // Limpar memória
        imagedestroy($originalImage);
        imagedestroy($newImage);
        
        if (!$success) {
            throw new Exception('Erro ao salvar imagem otimizada');
        }
        
        $newSize = filesize($filePath);
        $reduction = round((($originalSize - $newSize) / $originalSize) * 100, 1);
        
        logActivity("Imagem otimizada: " . basename($filePath), 'INFO', [
            'original_size' => formatBytes($originalSize),
            'new_size' => formatBytes($newSize),
            'reduction' => $reduction . '%',
            'dimensions' => "{$newWidth}x{$newHeight}"
        ]);
        
    } catch (Exception $e) {
        // Se otimização falhar, manter arquivo original
        error_log("Erro na otimização da imagem: " . $e->getMessage());
        logActivity("Erro na otimização: " . $e->getMessage(), 'WARNING');
    }
}

/**
 * Obter informações do arquivo
 */
function getFileInfo($filePath, $fileName) {
    $fileSize = filesize($filePath);
    $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
    
    $info = [
        'filename' => $fileName,
        'original_name' => $_FILES['comprovante']['name'] ?? $fileName,
        'size' => $fileSize,
        'size_formatted' => formatBytes($fileSize),
        'type' => $extension,
        'url' => 'view_comprovante.php?file=' . urlencode($fileName),
        'download_url' => 'view_comprovante.php?file=' . urlencode($fileName) . '&download=1',
        'upload_date' => date('Y-m-d H:i:s'),
        'hash' => hash_file('sha256', $filePath)
    ];
    
    // Adicionar informações específicas do tipo
    if (in_array($extension, ['jpg', 'jpeg', 'png'])) {
        $imageInfo = getimagesize($filePath);
        if ($imageInfo) {
            $info['width'] = $imageInfo[0];
            $info['height'] = $imageInfo[1];
            $info['dimensions'] = $imageInfo[0] . 'x' . $imageInfo[1];
        }
    }
    
    return $info;
}

/*
==============================================
 EXEMPLOS DE USO:
==============================================

# Upload via JavaScript/Fetch
const formData = new FormData();
formData.append('comprovante', fileInput.files[0]);
formData.append('casa_id', '1');
formData.append('mes', '6');
formData.append('ano', '2025');

fetch('/upload_comprovante.php', {
    method: 'POST',
    body: formData
})
.then(response => response.json())
.then(data => {
    if (data.success) {
        console.log('Upload realizado:', data.data);
    } else {
        console.error('Erro no upload:', data.error);
    }
});

# Upload via cURL
curl -X POST \
  -H "Authorization: Bearer YOUR_SESSION" \
  -F "comprovante=@/path/to/file.jpg" \
  -F "casa_id=1" \
  -F "mes=6" \
  -F "ano=2025" \
  https://seu-dominio.com/upload_comprovante.php

==============================================
 ESTRUTURA DE RESPOSTA:
==============================================

# Sucesso
{
    "success": true,
    "message": "Comprovante enviado com sucesso!",
    "data": {
        "filename": "comprovante_casa01_06_2025_1640995200_a1b2c3d4.jpg",
        "original_name": "recibo.jpg",
        "size": 245760,
        "size_formatted": "240 KB",
        "type": "jpg",
        "url": "view_comprovante.php?file=comprovante_casa01_06_2025_1640995200_a1b2c3d4.jpg",
        "download_url": "view_comprovante.php?file=comprovante_casa01_06_2025_1640995200_a1b2c3d4.jpg&download=1",
        "upload_date": "2025-06-20 15:30:45",
        "width": 1200,
        "height": 800,
        "dimensions": "1200x800",
        "hash": "sha256_hash_here"
    }
}

# Erro
{
    "success": false,
    "error": "Arquivo muito grande. Tamanho máximo: 5 MB",
    "code": 400
}

==============================================
*/
?>