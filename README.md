# R4T3 - Suite de Ferramentas para TI

**R4T3** é um script em PowerShell robusto desenvolvido para profissionais de TI, administradores de sistemas e usuários avançados que desejam automatizar tarefas de manutenção, configuração e segurança em ambientes Windows.

## 🚀 Funcionalidades

O script é dividido em módulos para facilitar o uso:

### 1. 📦 Instalação de Programas Essenciais
Instale softwares populares em massa ou individualmente usando o `winget` (Windows Package Manager).
- Suporte a navegadores (Chrome, Firefox), utilitários (7-Zip, WinRAR), ferramentas dev (VS Code, Git, Python) e comunicação (Teams, Zoom, Slack).
- Verificação e instalação automática do `App Installer` se necessário.

### 2. ⚙️ Configurações de GPO (Group Policy)
Aplique configurações de sistema rapidamente sem abrir o editor de políticas:
- Habilitar/Desabilitar Windows Update.
- Controle de UAC (User Account Control).
- Política de Senhas Fortes.
- Bloqueio/Desbloqueio de armazenamento USB.
- Configuração de Firewall e Remote Desktop (RDP).
- Backup das políticas locais.

### 3. 👥 Gerenciamento de Usuários e Domínio
Ferramentas para administração de contas locais e AD:
- Criação interativa de usuários locais (Padrão e Admin).
- **Criação em lote (Bulk)** a partir de CSV, com opção de senha manual ou **geração automática de senhas seguras**.
- Ingresso de máquinas no domínio.
- Criação de usuários no Active Directory.

### 4. 🛡️ Verificação de Segurança
Auditoria básica do sistema:
- Status do Windows Defender e Firewall.
- Varredura de serviços desnecessários e portas abertas.
- Detecção de contas com senhas em branco.
- Relatório completo de segurança exportável.

### 5. 🔧 Manutenção do Sistema
Rotinas de limpeza e otimização:
- Limpeza de disco (Temp, Cache, Lixeira).
- Verificação de integridade (SFC) e disco (CHKDSK).
- Backup de drivers.
- Criação de pontos de restauração.

## 📋 Pré-requisitos

- Windows 10 Versão 1709 ou superior (para suporte nativo ao Winget).
- PowerShell 5.1 ou superior.
- **Privilégios de Administrador** (o script solicita elevação automaticamente se necessário).

## 🚀 Como Usar

1. Baixe o arquivo `R4T3.ps1`.
2. Abra o PowerShell como Administrador.
3. Permita a execução de scripts (se ainda não tiver feito):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
4. Execute o script:
   ```powershell
   .\R4T3.ps1
   ```

## 📝 Exemplo de CSV para Criação em Lote

Ao usar a opção de "Criar múltiplos usuários", o arquivo CSV deve seguir este padrão:

```csv
Username,FullName,Description,IsAdmin
joao.silva,João Silva,Financeiro,false
maria.santos,Maria Santos,TI Support,true
```

## ⚠️ Aviso Legal

Este script altera configurações do sistema. Recomenda-se revisar o código e testar em um ambiente controlado antes de executar em produção.

## 🤝 Contribuição

Sinta-se à vontade para abrir Issues ou Pull Requests para melhorar o projeto!
