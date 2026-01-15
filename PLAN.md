# Plano de Melhorias para R4T3.ps1

## Resumo
Este documento descreve as melhorias propostas para o script `R4T3.ps1`, focando em segurança, modernização e robustez.

## Mudanças Propostas

### 1. Segurança: Melhorar `New-BulkUsers`
- **Problema:** A função atualmente usa uma senha hardcoded (`Temp@123456`) para todos os novos usuários.
- **Solução:**
  - Gerar uma senha aleatória forte para cada usuário.
  - Exibir a senha gerada no log/console para o administrador.
  - Forçar a alteração de senha no primeiro login (já implementado, mas a senha inicial única é um risco).

### 2. Modernização: Substituir `Get-WmiObject`
- **Problema:** `Get-WmiObject` é obsoleto e foi substituído por `Get-CimInstance` nas versões mais recentes do PowerShell.
- **Solução:** Substituir todas as chamadas `Get-WmiObject` por `Get-CimInstance`. Isso garante melhor compatibilidade com versões futuras e PowerShell Core.

### 3. Confiabilidade: Verificação do Winget
- **Problema:** A função `Install-WingetIfNeeded` pode falhar silenciosamente ou entrar em loop se a instalação do `App Installer` não funcionar (comum em Windows Server ou versões Enterprise LTSC).
- **Solução:** Adicionar verificações mais robustas e uma mensagem de erro clara se a instalação automática falhar, sugerindo instalação manual.

### 4. Code Style & Logging
- **Melhoria:** Padronizar o uso de logs.
- **Melhoria:** Adicionar timestamp no nome dos arquivos de backup de drivers e logs para evitar sobrescrita (já feito parcialmente, mas verificar consistência).

## Arquivos Afetados
- `R4T3.ps1`

## Verificação
- Testar a criação de usuários em massa com a nova lógica de senha.
- Verificar se os comandos CIM retornam as mesmas informações que os WMI.
