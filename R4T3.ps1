#Requires -RunAsAdministrator
<#
.SYNOPSIS
    R4T3 - Suite de Ferramentas para Profissionais de TI
.DESCRIPTION
    Script completo com múltiplas funções para administração de sistemas Windows
.AUTHOR
    R4T3 Project
.VERSION
    1.0
#>

# ============================================
# CONFIGURAÇÕES GLOBAIS
# ============================================
$Global:LogPath = "$env:SystemDrive\R4T3\Logs"
$Global:ConfigPath = "$env:SystemDrive\R4T3\Config"

# Criar diretórios necessários
if (-not (Test-Path $Global:LogPath)) {
    New-Item -ItemType Directory -Path $Global:LogPath -Force | Out-Null
}
if (-not (Test-Path $Global:ConfigPath)) {
    New-Item -ItemType Directory -Path $Global:ConfigPath -Force | Out-Null
}

# ============================================
# FUNÇÕES AUXILIARES
# ============================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogFile = Join-Path $Global:LogPath "R4T3_$(Get-Date -Format 'yyyyMMdd').log"
    $LogMessage = "[$Timestamp] [$Level] $Message"

    # Escrever no arquivo
    Add-Content -Path $LogFile -Value $LogMessage

    # Exibir no console com cores
    switch ($Level) {
        'Info' { Write-Host $Message -ForegroundColor Cyan }
        'Warning' { Write-Host $Message -ForegroundColor Yellow }
        'Error' { Write-Host $Message -ForegroundColor Red }
        'Success' { Write-Host $Message -ForegroundColor Green }
    }
}

function Show-Header {
    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "║                      R 4 T 3                               ║" -ForegroundColor Green
    Write-Host "║           SUITE DE FERRAMENTAS PARA TI                     ║" -ForegroundColor Cyan
    Write-Host "║                    v1.0                                    ║" -ForegroundColor Cyan
    Write-Host "║                                                            ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Wait-KeyPress {
    Write-Host "`nPressione qualquer tecla para continuar..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================
# MÓDULO 1: INSTALAÇÃO DE PROGRAMAS
# ============================================

function Install-WingetIfNeeded {
    Write-Log "Verificando se Winget está instalado..." -Level Info

    try {
        $winget = Get-Command winget -ErrorAction Stop
        Write-Log "Winget já está instalado." -Level Success
        return $true
    }
    catch {
        Write-Log "Winget não encontrado. Tentando instalar..." -Level Warning
        try {
            # Instalar App Installer (que inclui winget)
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
            Write-Log "Winget instalado com sucesso!" -Level Success
            return $true
        }
        catch {
            Write-Log "Erro ao instalar Winget: $_" -Level Error
            Write-Log "Por favor, instale o 'App Installer' manualmente pela Microsoft Store ou GitHub." -Level Warning
            return $false
        }
    }
}

function Show-SoftwareMenu {
    do {
        Show-Header
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "           INSTALAÇÃO DE PROGRAMAS ESSENCIAIS" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host " [1]  Google Chrome" -ForegroundColor White
        Write-Host " [2]  Mozilla Firefox" -ForegroundColor White
        Write-Host " [3]  Adobe Acrobat Reader DC" -ForegroundColor White
        Write-Host " [4]  7-Zip" -ForegroundColor White
        Write-Host " [5]  WinRAR" -ForegroundColor White
        Write-Host " [6]  RustDesk (Acesso Remoto)" -ForegroundColor White
        Write-Host " [7]  TeamViewer" -ForegroundColor White
        Write-Host " [8]  VLC Media Player" -ForegroundColor White
        Write-Host " [9]  Microsoft Office 365" -ForegroundColor White
        Write-Host " [10] LibreOffice" -ForegroundColor White
        Write-Host " [11] Notepad++" -ForegroundColor White
        Write-Host " [12] Visual Studio Code" -ForegroundColor White
        Write-Host " [13] Git" -ForegroundColor White
        Write-Host " [14] Python" -ForegroundColor White
        Write-Host " [15] Zoom" -ForegroundColor White
        Write-Host " [16] Microsoft Teams" -ForegroundColor White
        Write-Host " [17] Slack" -ForegroundColor White
        Write-Host " [18] FileZilla" -ForegroundColor White
        Write-Host " [19] PuTTY" -ForegroundColor White
        Write-Host " [20] Instalar TODOS os programas essenciais" -ForegroundColor Green
        Write-Host " [0]  Voltar ao menu principal" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host "Escolha uma opção"

        if ($choice -eq "0") {
            return
        }

        if (-not (Install-WingetIfNeeded)) {
            Write-Log "Não é possível instalar programas sem o Winget." -Level Error
            Wait-KeyPress
            continue
        }

        switch ($choice) {
            "1" { Install-Software -Name "Google Chrome" -WingetId "Google.Chrome" }
            "2" { Install-Software -Name "Mozilla Firefox" -WingetId "Mozilla.Firefox" }
            "3" { Install-Software -Name "Adobe Acrobat Reader DC" -WingetId "Adobe.Acrobat.Reader.64-bit" }
            "4" { Install-Software -Name "7-Zip" -WingetId "7zip.7zip" }
            "5" { Install-Software -Name "WinRAR" -WingetId "RARLab.WinRAR" }
            "6" { Install-Software -Name "RustDesk" -WingetId "RustDesk.RustDesk" }
            "7" { Install-Software -Name "TeamViewer" -WingetId "TeamViewer.TeamViewer" }
            "8" { Install-Software -Name "VLC Media Player" -WingetId "VideoLAN.VLC" }
            "9" { Install-Software -Name "Microsoft Office 365" -WingetId "Microsoft.Office" }
            "10" { Install-Software -Name "LibreOffice" -WingetId "TheDocumentFoundation.LibreOffice" }
            "11" { Install-Software -Name "Notepad++" -WingetId "Notepad++.Notepad++" }
            "12" { Install-Software -Name "Visual Studio Code" -WingetId "Microsoft.VisualStudioCode" }
            "13" { Install-Software -Name "Git" -WingetId "Git.Git" }
            "14" { Install-Software -Name "Python" -WingetId "Python.Python.3.12" }
            "15" { Install-Software -Name "Zoom" -WingetId "Zoom.Zoom" }
            "16" { Install-Software -Name "Microsoft Teams" -WingetId "Microsoft.Teams" }
            "17" { Install-Software -Name "Slack" -WingetId "SlackTechnologies.Slack" }
            "18" { Install-Software -Name "FileZilla" -WingetId "TimKosse.FileZilla.Client" }
            "19" { Install-Software -Name "PuTTY" -WingetId "PuTTY.PuTTY" }
            "20" { Install-AllEssentialSoftware }
            default { Write-Log "Opção inválida!" -Level Warning }
        }

        if ($choice -ne "0") {
            Wait-KeyPress
        }
    } while ($true)
}

function Install-Software {
    param(
        [string]$Name,
        [string]$WingetId
    )

    Write-Log "Instalando $Name..." -Level Info

    try {
        winget install --id $WingetId --silent --accept-package-agreements --accept-source-agreements

        if ($LASTEXITCODE -eq 0) {
            Write-Log "$Name instalado com sucesso!" -Level Success
        }
        else {
            Write-Log "Erro ao instalar $Name. Código de saída: $LASTEXITCODE" -Level Error
        }
    }
    catch {
        Write-Log "Erro ao instalar $Name: $_" -Level Error
    }
}

function Install-AllEssentialSoftware {
    $essentialSoftware = @(
        @{Name = "Google Chrome"; Id = "Google.Chrome" },
        @{Name = "Adobe Acrobat Reader"; Id = "Adobe.Acrobat.Reader.64-bit" },
        @{Name = "7-Zip"; Id = "7zip.7zip" },
        @{Name = "RustDesk"; Id = "RustDesk.RustDesk" },
        @{Name = "VLC Media Player"; Id = "VideoLAN.VLC" },
        @{Name = "Notepad++"; Id = "Notepad++.Notepad++" },
        @{Name = "Microsoft Teams"; Id = "Microsoft.Teams" }
    )

    Write-Log "Iniciando instalação de todos os programas essenciais..." -Level Info

    foreach ($software in $essentialSoftware) {
        Install-Software -Name $software.Name -WingetId $software.Id
    }

    Write-Log "Instalação em lote concluída!" -Level Success
}

# ============================================
# MÓDULO 2: CONFIGURAÇÕES DE GPO
# ============================================

function Show-GPOMenu {
    do {
        Show-Header
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "           CONFIGURAÇÕES DE GROUP POLICY (GPO)" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host " [1]  Desabilitar Windows Update automático" -ForegroundColor White
        Write-Host " [2]  Habilitar Windows Update automático" -ForegroundColor White
        Write-Host " [3]  Desabilitar UAC (User Account Control)" -ForegroundColor White
        Write-Host " [4]  Habilitar UAC" -ForegroundColor White
        Write-Host " [5]  Configurar política de senhas fortes" -ForegroundColor White
        Write-Host " [6]  Desabilitar USB Storage" -ForegroundColor White
        Write-Host " [7]  Habilitar USB Storage" -ForegroundColor White
        Write-Host " [8]  Configurar Firewall do Windows" -ForegroundColor White
        Write-Host " [9]  Desabilitar Remote Desktop" -ForegroundColor White
        Write-Host " [10] Habilitar Remote Desktop" -ForegroundColor White
        Write-Host " [11] Exportar políticas locais para backup" -ForegroundColor White
        Write-Host " [0]  Voltar ao menu principal" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host "Escolha uma opção"

        switch ($choice) {
            "1" { Set-WindowsUpdate -Enable $false }
            "2" { Set-WindowsUpdate -Enable $true }
            "3" { Set-UAC -Enable $false }
            "4" { Set-UAC -Enable $true }
            "5" { Set-PasswordPolicy }
            "6" { Set-USBStorage -Enable $false }
            "7" { Set-USBStorage -Enable $true }
            "8" { Configure-Firewall }
            "9" { Set-RemoteDesktop -Enable $false }
            "10" { Set-RemoteDesktop -Enable $true }
            "11" { Export-LocalPolicies }
            "0" { return }
            default { Write-Log "Opção inválida!" -Level Warning }
        }

        if ($choice -ne "0") {
            Wait-KeyPress
        }
    } while ($true)
}

function Set-WindowsUpdate {
    param([bool]$Enable)

    $status = if ($Enable) { "habilitado" } else { "desabilitado" }
    Write-Log "Configurando Windows Update como $status..." -Level Info

    try {
        $AUKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

        if (-not (Test-Path $AUKey)) {
            New-Item -Path $AUKey -Force | Out-Null
        }

        if ($Enable) {
            Set-ItemProperty -Path $AUKey -Name "NoAutoUpdate" -Value 0 -Type DWord
            Set-ItemProperty -Path $AUKey -Name "AUOptions" -Value 4 -Type DWord
        }
        else {
            Set-ItemProperty -Path $AUKey -Name "NoAutoUpdate" -Value 1 -Type DWord
        }

        Write-Log "Windows Update $status com sucesso!" -Level Success
    }
    catch {
        Write-Log "Erro ao configurar Windows Update: $_" -Level Error
    }
}

function Set-UAC {
    param([bool]$Enable)

    $status = if ($Enable) { "habilitado" } else { "desabilitado" }
    Write-Log "Configurando UAC como $status..." -Level Info

    try {
        $UACKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $value = if ($Enable) { 5 } else { 0 }

        Set-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorAdmin" -Value $value -Type DWord
        Set-ItemProperty -Path $UACKey -Name "EnableLUA" -Value $(if ($Enable) { 1 } else { 0 }) -Type DWord

        Write-Log "UAC $status com sucesso! Reinicialização necessária." -Level Success
    }
    catch {
        Write-Log "Erro ao configurar UAC: $_" -Level Error
    }
}

function Set-PasswordPolicy {
    Write-Log "Configurando política de senhas fortes..." -Level Info

    try {
        # Requer senha complexa
        net accounts /minpwlen:8

        # Máximo de dias para senha
        net accounts /maxpwage:90

        # Mínimo de dias para senha
        net accounts /minpwage:1

        # Histórico de senhas
        net accounts /uniquepw:5

        Write-Log "Política de senhas configurada com sucesso!" -Level Success
        Write-Log "  - Tamanho mínimo: 8 caracteres" -Level Info
        Write-Log "  - Validade: 90 dias" -Level Info
        Write-Log "  - Histórico: 5 senhas" -Level Info
    }
    catch {
        Write-Log "Erro ao configurar política de senhas: $_" -Level Error
    }
}

function Set-USBStorage {
    param([bool]$Enable)

    $status = if ($Enable) { "habilitado" } else { "desabilitado" }
    Write-Log "Configurando USB Storage como $status..." -Level Info

    try {
        $USBKey = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
        $value = if ($Enable) { 3 } else { 4 }

        Set-ItemProperty -Path $USBKey -Name "Start" -Value $value -Type DWord

        Write-Log "USB Storage $status com sucesso!" -Level Success
    }
    catch {
        Write-Log "Erro ao configurar USB Storage: $_" -Level Error
    }
}

function Configure-Firewall {
    Write-Log "Configurando Firewall do Windows..." -Level Info

    try {
        # Habilitar firewall para todos os perfis
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

        # Bloquear conexões de entrada por padrão
        Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block

        # Permitir conexões de saída
        Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultOutboundAction Allow

        Write-Log "Firewall configurado com sucesso!" -Level Success
        Write-Log "  - Todos os perfis habilitados" -Level Info
        Write-Log "  - Entrada: Bloqueada por padrão" -Level Info
        Write-Log "  - Saída: Permitida" -Level Info
    }
    catch {
        Write-Log "Erro ao configurar Firewall: $_" -Level Error
    }
}

function Set-RemoteDesktop {
    param([bool]$Enable)

    $status = if ($Enable) { "habilitado" } else { "desabilitado" }
    Write-Log "Configurando Remote Desktop como $status..." -Level Info

    try {
        $RDPKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        $value = if ($Enable) { 0 } else { 1 }

        Set-ItemProperty -Path $RDPKey -Name "fDenyTSConnections" -Value $value -Type DWord

        if ($Enable) {
            # Habilitar regra de firewall para RDP
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
        }
        else {
            # Desabilitar regra de firewall para RDP
            Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
        }

        Write-Log "Remote Desktop $status com sucesso!" -Level Success
    }
    catch {
        Write-Log "Erro ao configurar Remote Desktop: $_" -Level Error
    }
}

function Export-LocalPolicies {
    Write-Log "Exportando políticas locais..." -Level Info

    try {
        $backupPath = Join-Path $Global:ConfigPath "PolicyBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        secedit /export /cfg $backupPath

        Write-Log "Políticas exportadas para: $backupPath" -Level Success
    }
    catch {
        Write-Log "Erro ao exportar políticas: $_" -Level Error
    }
}

# ============================================
# MÓDULO 3: GERENCIAMENTO DE USUÁRIOS E DOMÍNIO
# ============================================

function Show-UserManagementMenu {
    do {
        Show-Header
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "      GERENCIAMENTO DE USUÁRIOS E DOMÍNIO" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host " [1]  Criar usuário local (Padrão)" -ForegroundColor White
        Write-Host " [2]  Criar usuário local (Administrador)" -ForegroundColor White
        Write-Host " [3]  Listar usuários locais" -ForegroundColor White
        Write-Host " [4]  Remover usuário local" -ForegroundColor White
        Write-Host " [5]  Alterar senha de usuário" -ForegroundColor White
        Write-Host " [6]  Adicionar máquina ao domínio" -ForegroundColor White
        Write-Host " [7]  Verificar status do domínio" -ForegroundColor White
        Write-Host " [8]  Criar usuário no Active Directory" -ForegroundColor White
        Write-Host " [9]  Criar múltiplos usuários (em lote)" -ForegroundColor White
        Write-Host " [0]  Voltar ao menu principal" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host "Escolha uma opção"

        switch ($choice) {
            "1" { New-LocalUser_Interactive -IsAdmin $false }
            "2" { New-LocalUser_Interactive -IsAdmin $true }
            "3" { Get-LocalUsersList }
            "4" { Remove-LocalUser_Interactive }
            "5" { Set-UserPassword_Interactive }
            "6" { Join-DomainInteractive }
            "7" { Get-DomainStatus }
            "8" { New-ADUser_Interactive }
            "9" { New-BulkUsers }
            "0" { return }
            default { Write-Log "Opção inválida!" -Level Warning }
        }

        if ($choice -ne "0") {
            Wait-KeyPress
        }
    } while ($true)
}

function New-LocalUser_Interactive {
    param([bool]$IsAdmin)

    $userType = if ($IsAdmin) { "Administrador" } else { "Padrão" }
    Write-Host "`n--- Criar Usuário Local ($userType) ---`n" -ForegroundColor Yellow

    $username = Read-Host "Nome do usuário"
    $fullName = Read-Host "Nome completo"
    $description = Read-Host "Descrição (opcional)"
    $password = Read-Host "Senha" -AsSecureString

    try {
        # Criar usuário
        New-LocalUser -Name $username -Password $password -FullName $fullName -Description $description -ErrorAction Stop
        Write-Log "Usuário '$username' criado com sucesso!" -Level Success

        # Adicionar ao grupo de administradores se necessário
        if ($IsAdmin) {
            Add-LocalGroupMember -Group "Administradores" -Member $username -ErrorAction Stop
            Write-Log "Usuário adicionado ao grupo de Administradores" -Level Success
        }
    }
    catch {
        Write-Log "Erro ao criar usuário: $_" -Level Error
    }
}

function Get-LocalUsersList {
    Write-Host "`n--- Usuários Locais ---`n" -ForegroundColor Yellow

    try {
        $users = Get-LocalUser | Select-Object Name, FullName, Enabled, LastLogon
        $users | Format-Table -AutoSize
    }
    catch {
        Write-Log "Erro ao listar usuários: $_" -Level Error
    }
}

function Remove-LocalUser_Interactive {
    Write-Host "`n--- Remover Usuário Local ---`n" -ForegroundColor Yellow

    Get-LocalUsersList

    $username = Read-Host "`nNome do usuário para remover"
    $confirm = Read-Host "Tem certeza que deseja remover '$username'? (S/N)"

    if ($confirm -eq "S" -or $confirm -eq "s") {
        try {
            Remove-LocalUser -Name $username -ErrorAction Stop
            Write-Log "Usuário '$username' removido com sucesso!" -Level Success
        }
        catch {
            Write-Log "Erro ao remover usuário: $_" -Level Error
        }
    }
    else {
        Write-Log "Operação cancelada." -Level Info
    }
}

function Set-UserPassword_Interactive {
    Write-Host "`n--- Alterar Senha de Usuário ---`n" -ForegroundColor Yellow

    Get-LocalUsersList

    $username = Read-Host "`nNome do usuário"
    $password = Read-Host "Nova senha" -AsSecureString

    try {
        Set-LocalUser -Name $username -Password $password -ErrorAction Stop
        Write-Log "Senha do usuário '$username' alterada com sucesso!" -Level Success
    }
    catch {
        Write-Log "Erro ao alterar senha: $_" -Level Error
    }
}

function Join-DomainInteractive {
    Write-Host "`n--- Adicionar Máquina ao Domínio ---`n" -ForegroundColor Yellow

    $domain = Read-Host "Nome do domínio"
    $ou = Read-Host "OU (Organizational Unit) - opcional, pressione Enter para pular"
    $username = Read-Host "Usuário com permissão no domínio"
    $password = Read-Host "Senha" -AsSecureString

    try {
        $credential = New-Object System.Management.Automation.PSCredential($username, $password)

        if ($ou) {
            Add-Computer -DomainName $domain -OUPath $ou -Credential $credential -Force -ErrorAction Stop
        }
        else {
            Add-Computer -DomainName $domain -Credential $credential -Force -ErrorAction Stop
        }

        Write-Log "Máquina adicionada ao domínio '$domain' com sucesso!" -Level Success
        Write-Log "Reinicialização necessária para concluir." -Level Warning

        $restart = Read-Host "`nDeseja reiniciar agora? (S/N)"
        if ($restart -eq "S" -or $restart -eq "s") {
            Restart-Computer -Force
        }
    }
    catch {
        Write-Log "Erro ao adicionar ao domínio: $_" -Level Error
    }
}

function Get-DomainStatus {
    Write-Host "`n--- Status do Domínio ---`n" -ForegroundColor Yellow

    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem

        Write-Host "Nome do Computador: " -NoNewline
        Write-Host $computerSystem.Name -ForegroundColor Cyan

        Write-Host "Parte do Domínio: " -NoNewline
        if ($computerSystem.PartOfDomain) {
            Write-Host "Sim" -ForegroundColor Green
            Write-Host "Nome do Domínio: " -NoNewline
            Write-Host $computerSystem.Domain -ForegroundColor Cyan
        }
        else {
            Write-Host "Não (Workgroup)" -ForegroundColor Yellow
            Write-Host "Workgroup: " -NoNewline
            Write-Host $computerSystem.Workgroup -ForegroundColor Cyan
        }
    }
    catch {
        Write-Log "Erro ao verificar status do domínio: $_" -Level Error
    }
}

function New-ADUser_Interactive {
    Write-Host "`n--- Criar Usuário no Active Directory ---`n" -ForegroundColor Yellow

    # Verificar se o módulo AD está disponível
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Módulo ActiveDirectory não encontrado!" -Level Error
        Write-Log "Instale com: Install-WindowsFeature RSAT-AD-PowerShell" -Level Info
        return
    }

    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    $username = Read-Host "Nome do usuário (SamAccountName)"
    $firstName = Read-Host "Primeiro nome"
    $lastName = Read-Host "Sobrenome"
    $displayName = "$firstName $lastName"
    $email = Read-Host "Email"
    $ou = Read-Host "OU (Distinguished Name)"
    $password = Read-Host "Senha" -AsSecureString

    try {
        New-ADUser -Name $displayName `
            -GivenName $firstName `
            -Surname $lastName `
            -SamAccountName $username `
            -UserPrincipalName "$username@$((Get-ADDomain).DNSRoot)" `
            -EmailAddress $email `
            -Path $ou `
            -AccountPassword $password `
            -Enabled $true `
            -ChangePasswordAtLogon $true `
            -ErrorAction Stop

        Write-Log "Usuário AD '$username' criado com sucesso!" -Level Success
    }
    catch {
        Write-Log "Erro ao criar usuário AD: $_" -Level Error
    }
}

function New-BulkUsers {
    Write-Host "`n--- Criar Múltiplos Usuários ---`n" -ForegroundColor Yellow
    Write-Host "Formato CSV esperado: Username,FullName,Description,IsAdmin(true/false)" -ForegroundColor Gray

    $csvPath = Read-Host "`nCaminho do arquivo CSV"

    if (-not (Test-Path $csvPath)) {
        Write-Log "Arquivo não encontrado!" -Level Error
        return
    }

    Write-Host "`nOpções de Senha:"
    Write-Host "[1] Definir uma senha única para todos (Manual)"
    Write-Host "[2] Gerar senhas aleatórias (Recomendado/Seguro)"
    $pwdChoice = Read-Host "Escolha uma opção"

    $manualPassword = $null
    if ($pwdChoice -eq "1") {
        $manualPassword = Read-Host "Digite a senha padrão" -AsSecureString
    }

    try {
        $users = Import-Csv -Path $csvPath
        $count = 0

        foreach ($user in $users) {
            $password = $null
            $displayPwd = ""

            if ($pwdChoice -eq "1") {
                $password = $manualPassword
                $displayPwd = "( Definida Manualmente )"
            }
            else {
                # Gerar senha aleatória forte (14 caracteres, incluindo especiais)
                $charSet = 33..126
                $rngPwd = -join ($charSet | Get-Random -Count 14 | ForEach-Object { [char]$_ })
                $password = ConvertTo-SecureString $rngPwd -AsPlainText -Force
                $displayPwd = $rngPwd
            }

            try {
                New-LocalUser -Name $user.Username -Password $password -FullName $user.FullName -Description $user.Description -ErrorAction Stop

                if ($user.IsAdmin -eq "true") {
                    Add-LocalGroupMember -Group "Administradores" -Member $user.Username -ErrorAction Stop
                }

                $count++
                Write-Log "Usuário '$($user.Username)' criado com sucesso!" -Level Success
                
                if ($pwdChoice -ne "1") {
                    Write-Host "    -> Senha: $displayPwd" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Log "Erro ao criar usuário '$($user.Username)': $_" -Level Error
            }
        }

        Write-Log "`n$count usuário(s) criado(s) com sucesso!" -Level Success
        if ($pwdChoice -eq "1") {
            Write-Log "Senha padrão aplicada. Solicite aos usuários que alterem no primeiro login." -Level Warning
        }
    }
    catch {
        Write-Log "Erro ao processar arquivo CSV: $_" -Level Error
    }
}

# ============================================
# MÓDULO 4: VERIFICAÇÃO DE SEGURANÇA
# ============================================

function Show-SecurityMenu {
    do {
        Show-Header
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "           VERIFICAÇÃO DE SEGURANÇA" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host " [1]  Verificar status do Windows Defender" -ForegroundColor White
        Write-Host " [2]  Verificar atualizações do Windows" -ForegroundColor White
        Write-Host " [3]  Verificar Firewall" -ForegroundColor White
        Write-Host " [4]  Verificar política de senhas" -ForegroundColor White
        Write-Host " [5]  Listar serviços desnecessários em execução" -ForegroundColor White
        Write-Host " [6]  Verificar portas abertas" -ForegroundColor White
        Write-Host " [7]  Auditoria de compartilhamentos de rede" -ForegroundColor White
        Write-Host " [8]  Verificar contas com senha em branco" -ForegroundColor White
        Write-Host " [9]  Relatório completo de segurança" -ForegroundColor White
        Write-Host " [10] Executar scan de malware (Windows Defender)" -ForegroundColor White
        Write-Host " [0]  Voltar ao menu principal" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host "Escolha uma opção"

        switch ($choice) {
            "1" { Test-WindowsDefender }
            "2" { Test-WindowsUpdates }
            "3" { Test-FirewallStatus }
            "4" { Test-PasswordPolicy }
            "5" { Get-UnnecessaryServices }
            "6" { Get-OpenPorts }
            "7" { Get-NetworkShares }
            "8" { Test-BlankPasswords }
            "9" { Get-SecurityReport }
            "10" { Start-DefenderScan }
            "0" { return }
            default { Write-Log "Opção inválida!" -Level Warning }
        }

        if ($choice -ne "0") {
            Wait-KeyPress
        }
    } while ($true)
}

function Test-WindowsDefender {
    Write-Host "`n--- Status do Windows Defender ---`n" -ForegroundColor Yellow

    try {
        $defenderStatus = Get-MpComputerStatus

        Write-Host "Antivírus habilitado: " -NoNewline
        if ($defenderStatus.AntivirusEnabled) {
            Write-Host "Sim" -ForegroundColor Green
        }
        else {
            Write-Host "Não" -ForegroundColor Red
        }

        Write-Host "Proteção em tempo real: " -NoNewline
        if ($defenderStatus.RealTimeProtectionEnabled) {
            Write-Host "Ativa" -ForegroundColor Green
        }
        else {
            Write-Host "Inativa" -ForegroundColor Red
        }

        Write-Host "Última verificação: " -NoNewline
        Write-Host $defenderStatus.AntivirusScanAge -ForegroundColor Cyan

        Write-Host "Definições atualizadas em: " -NoNewline
        Write-Host $defenderStatus.AntivirusSignatureLastUpdated -ForegroundColor Cyan
    }
    catch {
        Write-Log "Erro ao verificar Windows Defender: $_" -Level Error
    }
}

function Test-WindowsUpdates {
    Write-Host "`n--- Verificando Atualizações do Windows ---`n" -ForegroundColor Yellow

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()

        Write-Log "Procurando por atualizações..." -Level Info
        $searchResult = $searcher.Search("IsInstalled=0")

        if ($searchResult.Updates.Count -eq 0) {
            Write-Log "Sistema está atualizado!" -Level Success
        }
        else {
            Write-Log "Foram encontradas $($searchResult.Updates.Count) atualizações pendentes:" -Level Warning
            foreach ($update in $searchResult.Updates) {
                Write-Host "  - $($update.Title)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Log "Erro ao verificar atualizações: $_" -Level Error
    }
}

function Test-FirewallStatus {
    Write-Host "`n--- Status do Firewall ---`n" -ForegroundColor Yellow

    try {
        $profiles = Get-NetFirewallProfile

        foreach ($profile in $profiles) {
            Write-Host "`nPerfil: " -NoNewline
            Write-Host $profile.Name -ForegroundColor Cyan
            Write-Host "  Habilitado: " -NoNewline
            if ($profile.Enabled) {
                Write-Host "Sim" -ForegroundColor Green
            }
            else {
                Write-Host "Não" -ForegroundColor Red
            }
            Write-Host "  Entrada: $($profile.DefaultInboundAction)" -ForegroundColor Gray
            Write-Host "  Saída: $($profile.DefaultOutboundAction)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Log "Erro ao verificar Firewall: $_" -Level Error
    }
}

function Test-PasswordPolicy {
    Write-Host "`n--- Política de Senhas ---`n" -ForegroundColor Yellow

    try {
        $output = net accounts
        $output | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
    }
    catch {
        Write-Log "Erro ao verificar política de senhas: $_" -Level Error
    }
}

function Get-UnnecessaryServices {
    Write-Host "`n--- Serviços Potencialmente Desnecessários ---`n" -ForegroundColor Yellow

    $unnecessaryServices = @(
        "Fax",
        "RemoteRegistry",
        "Telnet",
        "XblAuthManager",
        "XblGameSave",
        "XboxNetApiSvc"
    )

    try {
        foreach ($serviceName in $unnecessaryServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Write-Host "  [!] " -NoNewline -ForegroundColor Red
                Write-Host "$($service.DisplayName) está em execução" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Log "Erro ao verificar serviços: $_" -Level Error
    }
}

function Get-OpenPorts {
    Write-Host "`n--- Portas Abertas ---`n" -ForegroundColor Yellow

    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } |
        Select-Object LocalAddress, LocalPort, State |
        Sort-Object LocalPort -Unique

        $connections | Format-Table -AutoSize
    }
    catch {
        Write-Log "Erro ao verificar portas: $_" -Level Error
    }
}

function Get-NetworkShares {
    Write-Host "`n--- Compartilhamentos de Rede ---`n" -ForegroundColor Yellow

    try {
        $shares = Get-SmbShare | Where-Object { $_.Name -notlike "*$" }

        if ($shares.Count -eq 0) {
            Write-Log "Nenhum compartilhamento encontrado." -Level Info
        }
        else {
            $shares | Format-Table Name, Path, Description -AutoSize
        }
    }
    catch {
        Write-Log "Erro ao verificar compartilhamentos: $_" -Level Error
    }
}

function Test-BlankPasswords {
    Write-Host "`n--- Verificando Contas com Senha em Branco ---`n" -ForegroundColor Yellow

    try {
        $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        $found = $false

        foreach ($user in $users) {
            # Verificar se PasswordRequired está desabilitado usando CIM
            $userCim = Get-CimInstance -ClassName Win32_UserAccount -Filter "Name='$($user.Name)' AND LocalAccount=True"
            if ($userCim.PasswordRequired -eq $false) {
                Write-Host "  [!] " -NoNewline -ForegroundColor Red
                Write-Host "Usuário '$($user.Name)' não requer senha!" -ForegroundColor Yellow
                $found = $true
            }
        }

        if (-not $found) {
            Write-Log "Todos os usuários possuem senha configurada." -Level Success
        }
    }
    catch {
        Write-Log "Erro ao verificar senhas: $_" -Level Error
    }
}

function Get-SecurityReport {
    Write-Host "`n--- RELATÓRIO COMPLETO DE SEGURANÇA ---`n" -ForegroundColor Yellow

    $reportPath = Join-Path $Global:LogPath "SecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    Start-Transcript -Path $reportPath

    Write-Host "`n=== INFORMAÇÕES DO SISTEMA ===" -ForegroundColor Cyan
    Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsArchitecture

    Write-Host "`n=== WINDOWS DEFENDER ===" -ForegroundColor Cyan
    Test-WindowsDefender

    Write-Host "`n=== FIREWALL ===" -ForegroundColor Cyan
    Test-FirewallStatus

    Write-Host "`n=== POLÍTICA DE SENHAS ===" -ForegroundColor Cyan
    Test-PasswordPolicy

    Write-Host "`n=== SERVIÇOS DESNECESSÁRIOS ===" -ForegroundColor Cyan
    Get-UnnecessaryServices

    Write-Host "`n=== PORTAS ABERTAS ===" -ForegroundColor Cyan
    Get-OpenPorts

    Write-Host "`n=== COMPARTILHAMENTOS ===" -ForegroundColor Cyan
    Get-NetworkShares

    Stop-Transcript

    Write-Log "`nRelatório salvo em: $reportPath" -Level Success
}

function Start-DefenderScan {
    Write-Host "`n--- Executando Scan de Malware ---`n" -ForegroundColor Yellow

    Write-Host "[1] Quick Scan (Rápido)" -ForegroundColor White
    Write-Host "[2] Full Scan (Completo)" -ForegroundColor White

    $scanType = Read-Host "`nEscolha o tipo de scan"

    try {
        switch ($scanType) {
            "1" {
                Write-Log "Iniciando Quick Scan..." -Level Info
                Start-MpScan -ScanType QuickScan
            }
            "2" {
                Write-Log "Iniciando Full Scan (isso pode demorar)..." -Level Info
                Start-MpScan -ScanType FullScan
            }
            default {
                Write-Log "Opção inválida!" -Level Warning
                return
            }
        }

        Write-Log "Scan concluído!" -Level Success
    }
    catch {
        Write-Log "Erro ao executar scan: $_" -Level Error
    }
}

# ============================================
# MÓDULO 5: MANUTENÇÃO DO SISTEMA
# ============================================

function Show-MaintenanceMenu {
    do {
        Show-Header
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "           MANUTENÇÃO DO SISTEMA" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host " [1]  Limpeza de disco (Temp, Cache, etc)" -ForegroundColor White
        Write-Host " [2]  Verificar integridade do sistema (SFC)" -ForegroundColor White
        Write-Host " [3]  Verificar e reparar disco (CHKDSK)" -ForegroundColor White
        Write-Host " [4]  Otimizar/Desfragmentar disco" -ForegroundColor White
        Write-Host " [5]  Limpar log de eventos" -ForegroundColor White
        Write-Host " [6]  Coletar informações do sistema" -ForegroundColor White
        Write-Host " [7]  Gerenciar programas de inicialização" -ForegroundColor White
        Write-Host " [8]  Verificar saúde do disco (SMART)" -ForegroundColor White
        Write-Host " [9]  Backup de drivers" -ForegroundColor White
        Write-Host " [10] Criar ponto de restauração" -ForegroundColor White
        Write-Host " [0]  Voltar ao menu principal" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host "Escolha uma opção"

        switch ($choice) {
            "1" { Start-DiskCleanup }
            "2" { Start-SFCScan }
            "3" { Start-DiskCheck }
            "4" { Start-DiskOptimization }
            "5" { Clear-EventLogs }
            "6" { Get-SystemInformation }
            "7" { Get-StartupPrograms }
            "8" { Test-DiskHealth }
            "9" { Backup-Drivers }
            "10" { New-RestorePoint }
            "0" { return }
            default { Write-Log "Opção inválida!" -Level Warning }
        }

        if ($choice -ne "0") {
            Wait-KeyPress
        }
    } while ($true)
}

function Start-DiskCleanup {
    Write-Host "`n--- Limpeza de Disco ---`n" -ForegroundColor Yellow

    Write-Log "Iniciando limpeza de arquivos temporários..." -Level Info

    try {
        # Limpar pasta Temp do usuário
        $tempPath = [System.IO.Path]::GetTempPath()
        Write-Log "Limpando: $tempPath" -Level Info
        Get-ChildItem -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

        # Limpar pasta Temp do Windows
        Write-Log "Limpando: C:\Windows\Temp" -Level Info
        Get-ChildItem -Path "C:\Windows\Temp" -Recurse -Force -ErrorAction SilentlyContinue |
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue

        # Limpar lixeira
        Write-Log "Esvaziando lixeira..." -Level Info
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue

        # Executar Disk Cleanup
        Write-Log "Executando Disk Cleanup..." -Level Info
        Start-Process "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait

        Write-Log "Limpeza concluída!" -Level Success
    }
    catch {
        Write-Log "Erro durante limpeza: $_" -Level Error
    }
}

function Start-SFCScan {
    Write-Host "`n--- Verificação de Integridade do Sistema ---`n" -ForegroundColor Yellow

    Write-Log "Executando SFC /scannow (isso pode demorar)..." -Level Info

    try {
        Start-Process "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow
        Write-Log "Verificação SFC concluída! Verifique os logs em C:\Windows\Logs\CBS" -Level Success
    }
    catch {
        Write-Log "Erro ao executar SFC: $_" -Level Error
    }
}

function Start-DiskCheck {
    Write-Host "`n--- Verificação de Disco ---`n" -ForegroundColor Yellow

    $drive = Read-Host "Digite a letra do drive (ex: C)"

    Write-Log "Agendando CHKDSK para a próxima reinicialização..." -Level Info

    try {
        chkdsk "${drive}:" /F /R /X
        Write-Log "CHKDSK agendado. Reinicie o computador para executar." -Level Success
    }
    catch {
        Write-Log "Erro ao agendar CHKDSK: $_" -Level Error
    }
}

function Start-DiskOptimization {
    Write-Host "`n--- Otimização de Disco ---`n" -ForegroundColor Yellow

    $drive = Read-Host "Digite a letra do drive (ex: C)"

    try {
        $volume = Get-Volume -DriveLetter $drive

        Write-Log "Otimizando disco $drive..." -Level Info
        Optimize-Volume -DriveLetter $drive -Verbose

        Write-Log "Otimização concluída!" -Level Success
    }
    catch {
        Write-Log "Erro ao otimizar disco: $_" -Level Error
    }
}

function Clear-EventLogs {
    Write-Host "`n--- Limpar Logs de Eventos ---`n" -ForegroundColor Yellow

    $confirm = Read-Host "Tem certeza que deseja limpar todos os logs de eventos? (S/N)"

    if ($confirm -eq "S" -or $confirm -eq "s") {
        try {
            $logs = Get-EventLog -List

            foreach ($log in $logs) {
                Write-Log "Limpando log: $($log.Log)" -Level Info
                Clear-EventLog -LogName $log.Log -ErrorAction SilentlyContinue
            }

            Write-Log "Logs limpos com sucesso!" -Level Success
        }
        catch {
            Write-Log "Erro ao limpar logs: $_" -Level Error
        }
    }
    else {
        Write-Log "Operação cancelada." -Level Info
    }
}

function Get-SystemInformation {
    Write-Host "`n--- Informações do Sistema ---`n" -ForegroundColor Yellow

    try {
        $computerInfo = Get-ComputerInfo

        Write-Host "`nSISTEMA OPERACIONAL:" -ForegroundColor Cyan
        Write-Host "  Nome: $($computerInfo.OsName)"
        Write-Host "  Versão: $($computerInfo.OsVersion)"
        Write-Host "  Build: $($computerInfo.OsBuildNumber)"
        Write-Host "  Arquitetura: $($computerInfo.OsArchitecture)"

        Write-Host "`nHARDWARE:" -ForegroundColor Cyan
        Write-Host "  Fabricante: $($computerInfo.CsManufacturer)"
        Write-Host "  Modelo: $($computerInfo.CsModel)"
        Write-Host "  Processador: $($computerInfo.CsProcessors[0].Name)"
        Write-Host "  RAM Total: $([math]::Round($computerInfo.CsTotalPhysicalMemory / 1GB, 2)) GB"

        Write-Host "`nREDE:" -ForegroundColor Cyan
        Write-Host "  Nome do Computador: $($computerInfo.CsName)"
        Write-Host "  Domínio: $($computerInfo.CsDomain)"

        # Exportar para arquivo
        $reportPath = Join-Path $Global:LogPath "SystemInfo_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $computerInfo | Out-File -FilePath $reportPath

        Write-Log "`nRelatório completo salvo em: $reportPath" -Level Success
    }
    catch {
        Write-Log "Erro ao coletar informações: $_" -Level Error
    }
}

function Get-StartupPrograms {
    Write-Host "`n--- Programas de Inicialização ---`n" -ForegroundColor Yellow

    try {
        Write-Host "`nREGISTRO (HKLM):" -ForegroundColor Cyan
        $startupHKLM = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $startupHKLM.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            Write-Host "  - $($_.Name): $($_.Value)" -ForegroundColor Gray
        }

        Write-Host "`nREGISTRO (HKCU):" -ForegroundColor Cyan
        $startupHKCU = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        $startupHKCU.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            Write-Host "  - $($_.Name): $($_.Value)" -ForegroundColor Gray
        }

        Write-Host "`nPASTA DE INICIALIZAÇÃO:" -ForegroundColor Cyan
        $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        Get-ChildItem -Path $startupFolder -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "  - $($_.Name)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Log "Erro ao listar programas de inicialização: $_" -Level Error
    }
}

function Test-DiskHealth {
    Write-Host "`n--- Saúde do Disco (SMART) ---`n" -ForegroundColor Yellow

    try {
        $disks = Get-PhysicalDisk

        foreach ($disk in $disks) {
            Write-Host "`nDisco: $($disk.FriendlyName)" -ForegroundColor Cyan
            Write-Host "  Status: " -NoNewline

            if ($disk.HealthStatus -eq "Healthy") {
                Write-Host $disk.HealthStatus -ForegroundColor Green
            }
            else {
                Write-Host $disk.HealthStatus -ForegroundColor Red
            }

            Write-Host "  Tipo: $($disk.MediaType)"
            Write-Host "  Tamanho: $([math]::Round($disk.Size / 1GB, 2)) GB"
            Write-Host "  Número de série: $($disk.SerialNumber)"
        }
    }
    catch {
        Write-Log "Erro ao verificar saúde do disco: $_" -Level Error
    }
}

function Backup-Drivers {
    Write-Host "`n--- Backup de Drivers ---`n" -ForegroundColor Yellow

    $backupPath = Join-Path $Global:ConfigPath "DriverBackup_$(Get-Date -Format 'yyyyMMdd')"

    try {
        if (-not (Test-Path $backupPath)) {
            New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        }

        Write-Log "Exportando drivers para: $backupPath" -Level Info

        # Usar DISM para exportar drivers
        dism /online /export-driver /destination:$backupPath

        Write-Log "Backup de drivers concluído!" -Level Success
    }
    catch {
        Write-Log "Erro ao fazer backup de drivers: $_" -Level Error
    }
}

function New-RestorePoint {
    Write-Host "`n--- Criar Ponto de Restauração ---`n" -ForegroundColor Yellow

    $description = Read-Host "Descrição do ponto de restauração"

    try {
        # Habilitar criação de pontos de restauração
        Enable-ComputerRestore -Drive "$env:SystemDrive\"

        Write-Log "Criando ponto de restauração..." -Level Info
        Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS"

        Write-Log "Ponto de restauração criado com sucesso!" -Level Success
    }
    catch {
        Write-Log "Erro ao criar ponto de restauração: $_" -Level Error
        Write-Log "Certifique-se de que a Restauração do Sistema está habilitada" -Level Info
    }
}

# ============================================
# MENU PRINCIPAL
# ============================================

function Show-MainMenu {
    do {
        Show-Header
        Write-Host "Bem-vindo ao R4T3 - Suite de Ferramentas para TI!" -ForegroundColor Green
        Write-Host "Usuário: $env:USERNAME | Computador: $env:COMPUTERNAME`n" -ForegroundColor Gray

        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "                    MENU PRINCIPAL" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host " [1] Instalação de Programas Essenciais" -ForegroundColor White
        Write-Host " [2] Configurações de Group Policy (GPO)" -ForegroundColor White
        Write-Host " [3] Gerenciamento de Usuários e Domínio" -ForegroundColor White
        Write-Host " [4] Verificação de Segurança" -ForegroundColor White
        Write-Host " [5] Manutenção do Sistema" -ForegroundColor White
        Write-Host " [6] Ver Logs" -ForegroundColor White
        Write-Host " [0] Sair" -ForegroundColor Red
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        $choice = Read-Host "Escolha uma opção"

        switch ($choice) {
            "1" { Show-SoftwareMenu }
            "2" { Show-GPOMenu }
            "3" { Show-UserManagementMenu }
            "4" { Show-SecurityMenu }
            "5" { Show-MaintenanceMenu }
            "6" {
                Write-Host "`nAbrindo pasta de logs..." -ForegroundColor Info
                Start-Process explorer.exe $Global:LogPath
            }
            "0" {
                Write-Log "Encerrando R4T3..." -Level Info
                Write-Host "`nObrigado por usar o R4T3!" -ForegroundColor Green
                Start-Sleep -Seconds 2
                exit
            }
            default { Write-Log "Opção inválida!" -Level Warning; Wait-KeyPress }
        }
    } while ($true)
}

# ============================================
# INICIALIZAÇÃO
# ============================================

# Verificar se está executando como administrador
if (-not (Test-IsAdmin)) {
    Write-Host "ERRO: Este script requer privilégios de administrador!" -ForegroundColor Red
    Write-Host "Execute o PowerShell como Administrador e tente novamente." -ForegroundColor Yellow
    Wait-KeyPress
    exit
}

# Iniciar o programa
Write-Log "R4T3 iniciado" -Level Info
Show-MainMenu
