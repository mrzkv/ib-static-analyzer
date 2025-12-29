# 0. Проверка прав администратора и перезапуск при необходимости
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Запрос прав администратора для установки..." -ForegroundColor Yellow
    
    $scriptPath = $MyInvocation.MyCommand.Path
    if (!$scriptPath) {
        # Если скрипт запущен через iex (удаленно), сохраняем его во временный файл
        $scriptPath = Join-Path $env:TEMP "install_astguard.ps1"
        $scriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
        if (!$scriptContent) {
             # Попытка получить контент если ScriptBlock пустой (бывает при irm | iex)
             # В таком случае лучше просто попросить запустить от админа или скачать файл
             Write-Host "Ошибка: Не удалось определить путь к скрипту для перезапуска с правами администратора." -ForegroundColor Red
             Write-Host "Пожалуйста, запустите PowerShell от имени администратора и выполните команду установки снова." -ForegroundColor Yellow
             exit 1
        }
        $scriptContent | Out-File -FilePath $scriptPath -Encoding utf8
    }

    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    try {
        Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs -Wait
        exit
    } catch {
        Write-Host "Ошибка: Не удалось получить права администратора. Пожалуйста, запустите PowerShell от имени администратора вручную." -ForegroundColor Red
        exit 1
    }
}

# PowerShell script to install astguard

$ErrorActionPreference = "Stop"

Write-Host "=== Установка astguard ===" -ForegroundColor Cyan

# 1. Поиск интерпретатора Python
function Get-PythonCommand {
    $commands = @("python", "python3", "py")
    foreach ($cmd in $commands) {
        if (Get-Command $cmd -ErrorAction SilentlyContinue) {
            # Проверяем версию
            try {
                $v = & $cmd --version 2>$null
                if ($v -match "Python (\d+\.\d+)") {
                    $version = [version]$matches[1]
                    if ($version -ge [version]"3.8") {
                        return $cmd
                    }
                }
            } catch {}
        }
    }
    return $null
}

$PYTHON_CMD = Get-PythonCommand

if ($null -eq $PYTHON_CMD) {
    Write-Host "Ошибка: Python 3.8 или выше не найден. Пожалуйста, установите Python с сайта python.org" -ForegroundColor Red
    exit 1
}

Write-Host "Используется интерпретатор: " -NoNewline
Write-Host $PYTHON_CMD -ForegroundColor Green

# 3. Проверка наличия Git
if (!(Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Ошибка: git не найден. Пожалуйста, установите git (https://git-scm.com/)." -ForegroundColor Red
    exit 1
}

# 4. Установка пакета из GitHub
$REPO_URL = "git+https://github.com/mrzkv/ib-static-analyzer.git"

Write-Host "Установка пакета из GitHub..." -ForegroundColor Cyan

try {
    # 4.1 Пытаемся найти путь к Scripts Python
    try {
        $pythonScripts = (& $PYTHON_CMD -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null).Trim()
        if ($null -ne $pythonScripts -and (Test-Path $pythonScripts)) {
            if ($env:PATH -notlike "*$pythonScripts*") {
                Write-Host "Добавление $pythonScripts в PATH текущей сессии..." -ForegroundColor Gray
                $env:PATH = "$pythonScripts;" + $env:PATH
                
                # Также пытаемся добавить в пользовательский PATH на постоянной основе, если его там нет
                $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
                if ($userPath -notlike "*$pythonScripts*") {
                    Write-Host "Добавление $pythonScripts в пользовательский PATH навсегда..." -ForegroundColor Gray
                    # Аккуратно объединяем, чтобы не было лишних точек с запятой
                    if ($userPath -and !$userPath.EndsWith(";")) { $userPath += ";" }
                    [Environment]::SetEnvironmentVariable("Path", "$userPath$pythonScripts", "User")
                }
            }
        }
    } catch {
        Write-Host "Предупреждение: Не удалось автоматически определить путь к Python Scripts." -ForegroundColor Yellow
    }

    & $PYTHON_CMD -m pip install $REPO_URL --force-reinstall --break-system-packages
    Write-Host "`nУстановка завершена успешно!" -ForegroundColor Green
    
    # 4.2 Проверка доступности команды в текущей сессии
    if (!(Get-Command astguard -ErrorAction SilentlyContinue)) {
        Write-Host "`nВнимание: Команда 'astguard' может быть недоступна в этом окне без перезапуска." -ForegroundColor Yellow
        Write-Host "Попробуйте закрыть и снова открыть PowerShell." -ForegroundColor Yellow
        if ($null -ne $pythonScripts) {
            Write-Host "Или выполните следующую команду для настройки PATH в текущей сессии:" -ForegroundColor Yellow
            Write-Host "  `$env:PATH = `"$pythonScripts;`" + `$env:PATH" -ForegroundColor Cyan
        }
    }

    Write-Host "`nТеперь вы можете использовать команду: " -NoNewline
    Write-Host "astguard --help" -ForegroundColor Cyan
} catch {
    Write-Host "Ошибка при установке через pip. Попробуйте запустить PowerShell от имени администратора." -ForegroundColor Red
    exit 1
}
