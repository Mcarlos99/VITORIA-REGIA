<?php
/**
 * Sistema de Visualização Segura de Comprovantes - Condomínio Vitória Régia
 * 
 * Este arquivo gerencia a visualização segura de comprovantes:
 * - Controle de acesso autenticado
 * - Validação de nomes de arquivo
 * - Headers apropriados por tipo
 * - Logs de acesso
 * - Proteção contra ataques de path traversal
 * - Download controlado
 * 
 * Uso:
 * GET /view_comprovante.php?file=nome_do_arquivo.jpg
 * GET /view_comprovante.php?file=nome_do_arquivo.pdf&download=1
 * GET /view_comprovante.php?file=nome_do_arquivo.png&thumbnail=1
 */

require_once 'config.php';
require_once 'auth.php';

// Verificar autenticação
$auth = requireAuth();
$userInfo = getCurrentUser();

// Obter parâmetros
$filename = $_GET['file'] ?? '';
$isDownload = isset($_GET['download']) && $_GET['download'] == '1';
$isThumbnail = isset($_GET['thumbnail']) && $_GET['thumbnail'] == '1';
$showInfo = isset($_GET['info']) && $_GET['info'] == '1';

try {
    // Validar nome do arquivo
    $validatedFile = validateFileName($filename);
    
    // Obter caminho completo do arquivo
    $filePath = UPLOAD_DIR_COMPROVANTES . $validatedFile;
    
    // Verificar se arquivo existe
    if (!file_exists($filePath)) {
        throw new Exception('Arquivo não encontrado', 404);
    }
    
    // Verificar permissões do arquivo
    if (!is_readable($filePath)) {
        throw new Exception('Sem permissão para acessar o arquivo', 403);
    }
    
    // Log do acesso
    logFileAccess($validatedFile, $userInfo, $isDownload, $isThumbnail);
    
    // Processar requisição baseado no tipo
    if ($showInfo) {
        showFileInfo($filePath, $validatedFile);
    } elseif ($isThumbnail) {
        serveThumbnail($filePath, $validatedFile);
    } else {
        serveFile($filePath, $validatedFile, $isDownload);
    }
    
} catch (Exception $e) {
    handleError($e);
}

/**
 * Validar nome do arquivo
 */
function validateFileName($filename) {
    // Verificar se filename foi fornecido
    if (empty($filename)) {
        throw new Exception('Nome do arquivo não especificado', 400);
    }
    
    // Remover espaços e caracteres especiais
    $filename = trim($filename);
    
    // Verificar comprimento
    if (strlen($filename) > 255) {
        throw new Exception('Nome do arquivo muito longo', 400);
    }
    
    // Verificar padrão de nomenclatura esperado
    $pattern = '/^comprovante_casa\d{2}_\d{2}_\d{4}_\d+_[a-z0-9]{8}\.(jpg|jpeg|png|pdf)$/i';
    if (!preg_match($pattern, $filename)) {
        throw new Exception('Nome do arquivo inválido', 400);
    }
    
    // Verificar caracteres perigosos (path traversal)
    $dangerousChars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|', "\0"];
    foreach ($dangerousChars as $char) {
        if (strpos($filename, $char) !== false) {
            throw new Exception('Caracteres não permitidos no nome do arquivo', 400);
        }
    }
    
    // Verificar se é apenas o nome do arquivo (sem path)
    if (basename($filename) !== $filename) {
        throw new Exception('Caminho de arquivo não permitido', 400);
    }
    
    return $filename;
}

/**
 * Servir arquivo
 */
function serveFile($filePath, $filename, $isDownload = false) {
    $fileSize = filesize($filePath);
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    // Determinar Content-Type
    $contentType = getContentType($extension);
    
    // Configurar headers básicos
    header('Content-Type: ' . $contentType);
    header('Content-Length: ' . $fileSize);
    header('Accept-Ranges: bytes');
    
    // Headers de segurança
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('X-XSS-Protection: 1; mode=block');
    
    // Headers de cache (24 horas)
    $etag = md5_file($filePath);
    $lastModified = filemtime($filePath);
    
    header('ETag: "' . $etag . '"');
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $lastModified) . ' GMT');
    header('Cache-Control: private, max-age=86400');
    
    // Verificar cache do cliente
    $clientEtag = $_SERVER['HTTP_IF_NONE_MATCH'] ?? '';
    $clientModified = $_SERVER['HTTP_IF_MODIFIED_SINCE'] ?? '';
    
    if (($clientEtag && $clientEtag === '"' . $etag . '"') || 
        ($clientModified && strtotime($clientModified) >= $lastModified)) {
        http_response_code(304);
        exit;
    }
    
    // Definir disposição do arquivo
    if ($isDownload || $extension === 'pdf') {
        $dispositionType = $isDownload ? 'attachment' : 'inline';
        $safeName = generateSafeFilename($filename);
        header('Content-Disposition: ' . $dispositionType . '; filename="' . $safeName . '"');
    } else {
        header('Content-Disposition: inline');
    }
    
    // Verificar range request (para streaming)
    if (isset($_SERVER['HTTP_RANGE'])) {
        serveRangeRequest($filePath, $fileSize);
    } else {
        // Servir arquivo completo
        http_response_code(200);
        readfile($filePath);
    }
}

/**
 * Servir thumbnail (miniatura) para imagens
 */
function serveThumbnail($filePath, $filename) {
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    // Verificar se é imagem
    if (!in_array($extension, ['jpg', 'jpeg', 'png'])) {
        throw new Exception('Thumbnail disponível apenas para imagens', 400);
    }
    
    // Verificar se thumbnail já existe
    $thumbnailPath = generateThumbnailPath($filename);
    
    if (!file_exists($thumbnailPath) || filemtime($filePath) > filemtime($thumbnailPath)) {
        // Gerar thumbnail
        createThumbnail($filePath, $thumbnailPath, $extension);
    }
    
    // Servir thumbnail
    if (file_exists($thumbnailPath)) {
        $fileSize = filesize($thumbnailPath);
        
        header('Content-Type: ' . getContentType($extension));
        header('Content-Length: ' . $fileSize);
        header('Cache-Control: public, max-age=2592000'); // 30 dias
        header('X-Content-Type-Options: nosniff');
        
        readfile($thumbnailPath);
    } else {
        throw new Exception('Erro ao gerar thumbnail', 500);
    }
}

/**
 * Mostrar informações do arquivo
 */
function showFileInfo($filePath, $filename) {
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $fileSize = filesize($filePath);
    $lastModified = filemtime($filePath);
    
    $info = [
        'filename' => $filename,
        'size' => $fileSize,
        'size_formatted' => formatBytes($fileSize),
        'type' => $extension,
        'last_modified' => date('Y-m-d H:i:s', $lastModified),
        'hash' => hash_file('sha256', $filePath),
        'mime_type' => mime_content_type($filePath)
    ];
    
    // Informações específicas para imagens
    if (in_array($extension, ['jpg', 'jpeg', 'png'])) {
        $imageInfo = getimagesize($filePath);
        if ($imageInfo) {
            $info['width'] = $imageInfo[0];
            $info['height'] = $imageInfo[1];
            $info['dimensions'] = $imageInfo[0] . 'x' . $imageInfo[1];
            $info['bits'] = $imageInfo['bits'] ?? null;
            $info['channels'] = $imageInfo['channels'] ?? null;
        }
    }
    
    // Extrair informações do nome do arquivo
    if (preg_match('/comprovante_casa(\d+)_(\d+)_(\d+)_(\d+)_([a-z0-9]+)\.(.+)$/i', $filename, $matches)) {
        $info['casa_numero'] = (int) $matches[1];
        $info['mes'] = (int) $matches[2];
        $info['ano'] = (int) $matches[3];
        $info['timestamp'] = (int) $matches[4];
        $info['upload_date'] = date('Y-m-d H:i:s', $matches[4]);
        $info['random_id'] = $matches[5];
    }
    
    // Retornar como JSON
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($info, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
}

/**
 * Gerar caminho do thumbnail
 */
function generateThumbnailPath($filename) {
    $thumbnailDir = UPLOAD_DIR_COMPROVANTES . 'thumbnails/';
    
    // Criar diretório se não existir
    if (!is_dir($thumbnailDir)) {
        mkdir($thumbnailDir, 0755, true);
        
        // Criar .htaccess para thumbnails
        $htaccessContent = '# Proteção para thumbnails
<Files ~ "\.(jpg|jpeg|png)$">
    Order allow,deny
    Allow from all
</Files>
<Files ~ "\.">
    Order allow,deny
    Deny from all
</Files>';
        file_put_contents($thumbnailDir . '.htaccess', $htaccessContent);
    }
    
    $nameWithoutExt = pathinfo($filename, PATHINFO_FILENAME);
    return $thumbnailDir . 'thumb_' . $nameWithoutExt . '.jpg';
}

/**
 * Criar thumbnail
 */
function createThumbnail($sourcePath, $thumbnailPath, $extension) {
    $maxWidth = 300;
    $maxHeight = 300;
    $quality = 80;
    
    // Obter dimensões originais
    $imageInfo = getimagesize($sourcePath);
    if (!$imageInfo) {
        throw new Exception('Não foi possível ler a imagem', 500);
    }
    
    $originalWidth = $imageInfo[0];
    $originalHeight = $imageInfo[1];
    
    // Calcular novas dimensões mantendo proporção
    $ratio = min($maxWidth / $originalWidth, $maxHeight / $originalHeight);
    $newWidth = intval($originalWidth * $ratio);
    $newHeight = intval($originalHeight * $ratio);
    
    // Criar imagem do thumbnail
    $thumbnail = imagecreatetruecolor($newWidth, $newHeight);
    
    // Carregar imagem original
    switch ($extension) {
        case 'jpg':
        case 'jpeg':
            $originalImage = imagecreatefromjpeg($sourcePath);
            break;
        case 'png':
            $originalImage = imagecreatefrompng($sourcePath);
            // Configurar transparência
            imagealphablending($thumbnail, false);
            imagesavealpha($thumbnail, true);
            break;
        default:
            throw new Exception('Formato não suportado para thumbnail', 400);
    }
    
    if (!$originalImage) {
        throw new Exception('Erro ao carregar imagem original', 500);
    }
    
    // Redimensionar
    imagecopyresampled(
        $thumbnail, $originalImage,
        0, 0, 0, 0,
        $newWidth, $newHeight,
        $originalWidth, $originalHeight
    );
    
    // Salvar thumbnail como JPEG
    $success = imagejpeg($thumbnail, $thumbnailPath, $quality);
    
    // Limpar memória
    imagedestroy($originalImage);
    imagedestroy($thumbnail);
    
    if (!$success) {
        throw new Exception('Erro ao salvar thumbnail', 500);
    }
}

/**
 * Servir requisição de range (para streaming)
 */
function serveRangeRequest($filePath, $fileSize) {
    $ranges = parseRangeHeader($_SERVER['HTTP_RANGE'], $fileSize);
    
    if (empty($ranges)) {
        // Range inválido
        http_response_code(416);
        header('Content-Range: bytes */' . $fileSize);
        return;
    }
    
    if (count($ranges) == 1) {
        // Single range
        $range = $ranges[0];
        $start = $range['start'];
        $end = $range['end'];
        $contentLength = $end - $start + 1;
        
        http_response_code(206);
        header('Content-Range: bytes ' . $start . '-' . $end . '/' . $fileSize);
        header('Content-Length: ' . $contentLength);
        
        // Ler e enviar apenas a parte solicitada
        $handle = fopen($filePath, 'rb');
        fseek($handle, $start);
        
        $remaining = $contentLength;
        while ($remaining > 0 && !feof($handle)) {
            $chunkSize = min(8192, $remaining);
            echo fread($handle, $chunkSize);
            $remaining -= $chunkSize;
            flush();
        }
        
        fclose($handle);
    } else {
        // Multiple ranges (não implementado para simplicidade)
        http_response_code(416);
        header('Content-Range: bytes */' . $fileSize);
    }
}

/**
 * Parsear header Range
 */
function parseRangeHeader($rangeHeader, $fileSize) {
    if (!preg_match('/^bytes=(.+)$/', $rangeHeader, $matches)) {
        return [];
    }
    
    $ranges = [];
    $rangeSpecs = explode(',', $matches[1]);
    
    foreach ($rangeSpecs as $rangeSpec) {
        $rangeSpec = trim($rangeSpec);
        
        if (preg_match('/^(\d+)-(\d*)$/', $rangeSpec, $m)) {
            $start = (int) $m[1];
            $end = $m[2] !== '' ? (int) $m[2] : $fileSize - 1;
        } elseif (preg_match('/^-(\d+)$/', $rangeSpec, $m)) {
            $start = $fileSize - (int) $m[1];
            $end = $fileSize - 1;
        } else {
            continue; // Range inválido
        }
        
        // Validar range
        if ($start < 0) $start = 0;
        if ($end >= $fileSize) $end = $fileSize - 1;
        if ($start > $end) continue;
        
        $ranges[] = ['start' => $start, 'end' => $end];
    }
    
    return $ranges;
}

/**
 * Obter Content-Type apropriado
 */
function getContentType($extension) {
    $contentTypes = [
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'pdf' => 'application/pdf'
    ];
    
    return $contentTypes[$extension] ?? 'application/octet-stream';
}

/**
 * Gerar nome seguro para download
 */
function generateSafeFilename($filename) {
    // Extrair informações do nome do arquivo
    if (preg_match('/comprovante_casa(\d+)_(\d+)_(\d+)_\d+_[a-z0-9]+\.(.+)$/i', $filename, $matches)) {
        $casa = str_pad($matches[1], 2, '0', STR_PAD_LEFT);
        $mes = str_pad($matches[2], 2, '0', STR_PAD_LEFT);
        $ano = $matches[3];
        $ext = $matches[4];
        
        $meses = [
            '01' => 'Jan', '02' => 'Fev', '03' => 'Mar', '04' => 'Abr',
            '05' => 'Mai', '06' => 'Jun', '07' => 'Jul', '08' => 'Ago',
            '09' => 'Set', '10' => 'Out', '11' => 'Nov', '12' => 'Dez'
        ];
        
        $mesNome = $meses[$mes] ?? $mes;
        return "Comprovante_Casa{$casa}_{$mesNome}{$ano}.{$ext}";
    }
    
    return $filename;
}

/**
 * Log de acesso a arquivo
 */
function logFileAccess($filename, $userInfo, $isDownload, $isThumbnail) {
    $action = $isThumbnail ? 'thumbnail' : ($isDownload ? 'download' : 'view');
    
    logActivity("File $action: $filename", 'INFO', [
        'user' => $userInfo['username'],
        'user_id' => $userInfo['id'],
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'action' => $action,
        'file' => $filename
    ]);
    
    // Log adicional no banco para auditoria
    try {
        $pdo = getDB();
        $stmt = $pdo->prepare("
            INSERT INTO file_access_logs (user_id, filename, action, ip_address, user_agent, accessed_at)
            VALUES (?, ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $userInfo['id'],
            $filename,
            $action,
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
    } catch (Exception $e) {
        error_log("Erro ao registrar log de acesso: " . $e->getMessage());
    }
}

/**
 * Tratar erros
 */
function handleError($exception) {
    $code = $exception->getCode() ?: 500;
    $message = $exception->getMessage();
    
    // Log do erro
    error_log("View Comprovante Error: $message (Code: $code)");
    
    // Headers apropriados
    http_response_code($code);
    header('Content-Type: text/html; charset=utf-8');
    
    // Página de erro simples
    echo '<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Erro - Condomínio Vitória Régia</title>
    <style>
        body {
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
        }
        .error-icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        .error-title {
            color: #dc3545;
            font-size: 1.5em;
            margin-bottom: 15px;
        }
        .error-message {
            color: #666;
            margin-bottom: 30px;
        }
        .btn {
            background: linear-gradient(135deg, #2C5530, #4A7C59);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(44, 85, 48, 0.4);
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">❌</div>
        <div class="error-title">Erro ' . $code . '</div>
        <div class="error-message">' . htmlspecialchars($message) . '</div>
        <a href="javascript:history.back()" class="btn">← Voltar</a>
    </div>
</body>
</html>';
}

/*
==============================================
 TABELA ADICIONAL PARA LOGS:
==============================================

CREATE TABLE IF NOT EXISTS file_access_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    action ENUM('view', 'download', 'thumbnail') NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_user_date (user_id, accessed_at),
    INDEX idx_filename (filename),
    INDEX idx_action_date (action, accessed_at)
);

==============================================
 EXEMPLOS DE USO:
==============================================

# Visualizar imagem
https://seu-dominio.com/view_comprovante.php?file=comprovante_casa01_06_2025_1640995200_a1b2c3d4.jpg

# Download de arquivo
https://seu-dominio.com/view_comprovante.php?file=comprovante_casa01_06_2025_1640995200_a1b2c3d4.pdf&download=1

# Thumbnail de imagem
https://seu-dominio.com/view_comprovante.php?file=comprovante_casa01_06_2025_1640995200_a1b2c3d4.jpg&thumbnail=1

# Informações do arquivo (JSON)
https://seu-dominio.com/view_comprovante.php?file=comprovante_casa01_06_2025_1640995200_a1b2c3d4.jpg&info=1

# Via JavaScript
function visualizarComprovante(filename) {
    window.open(`/view_comprovante.php?file=${encodeURIComponent(filename)}`, '_blank');
}

function baixarComprovante(filename) {
    window.open(`/view_comprovante.php?file=${encodeURIComponent(filename)}&download=1`, '_blank');
}

==============================================
*/
?>