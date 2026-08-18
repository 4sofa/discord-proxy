# Discord WireGuard Auto

Launcher com código-fonte disponível para Windows x64 que usa WireGuard apenas durante a inicialização do Discord. Depois que o Discord fica estável, o launcher muda o TCP para a conexão direta sem reiniciar a instância.

O projeto é independente e não é afiliado ao Discord, WireGuard ou `wireproxy`.

## Código-fonte

- `src/DiscordWireGuardLauncher.cs`: launcher, proxy SOCKS5 local, troca WireGuard/direto e monitoramento do Discord.
- `Compilar-Executavel.ps1`: build automatizado para Windows; baixa e valida a dependência externa quando necessário.
- `THIRD_PARTY_NOTICES.md`: origem e licença do `wireproxy` incorporado.
- `.gitignore`: impede que perfis WireGuard, binários baixados e resultados do build sejam enviados ao GitHub.

O arquivo `Discord-WireGuard-Auto.exe` é gerado a partir do fonte C# e do binário público do `wireproxy` fixado pelo script. O perfil WireGuard nunca é incorporado ao executável.

## Compilar

Requisitos:

- Windows 10 ou 11 x64.
- Windows PowerShell 5.1 ou PowerShell 7.
- .NET Framework 4.x com o compilador C# instalado.
- Internet no primeiro build para baixar o `wireproxy` v1.1.3.

Abra o PowerShell na pasta do projeto e execute:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Compilar-Executavel.ps1
```

O script:

1. baixa o arquivo oficial `wireproxy_windows_amd64.tar.gz`, caso ele ainda não exista;
2. valida o SHA-256 do arquivo compactado;
3. extrai e valida novamente o SHA-256 do `wireproxy.exe`;
4. incorpora o `wireproxy` como recurso;
5. compila `Discord-WireGuard-Auto.exe` e mostra seu novo SHA-256.

Versão fixada da dependência: [`wireproxy` v1.1.3](https://github.com/windtf/wireproxy/releases/tag/v1.1.3).

## Uso

1. Obtenha seu próprio perfil WireGuard no formato `.conf`.
2. Deixe o túnel do aplicativo oficial WireGuard desligado.
3. Coloque exatamente um `.conf` ao lado de `Discord-WireGuard-Auto.exe` ou escolha o arquivo quando solicitado.
4. Execute `Discord-WireGuard-Auto.exe` como usuário normal.
5. Aguarde o Discord ficar estável e a janela do launcher fechar.

O aplicativo oficial WireGuard não precisa estar instalado. O launcher incorpora apenas o executável público do `wireproxy`; cada usuário precisa fornecer seu próprio perfil `.conf`.

### Escolher o perfil explicitamente

```powershell
.\Discord-WireGuard-Auto.exe --config "C:\caminho\perfil.conf"
```

### Manter o WireGuard por mais 10 segundos

Por padrão, a troca ocorre assim que o Discord fica estável. Para aguardar dez segundos adicionais:

```powershell
.\Discord-WireGuard-Auto.exe --proxy-seconds 10
```

### Testar sem reiniciar o Discord

```powershell
.\Discord-WireGuard-Auto.exe --check-only --config "C:\caminho\perfil.conf"
```

## Funcionamento

1. O launcher localiza duas portas TCP livres em `127.0.0.1`.
2. Inicia o WireGuard em modo usuário por meio do `wireproxy`.
3. Reinicia uma vez o Discord com `--proxy-server`, apontando para o SOCKS5 local.
4. Mantém o TCP pelo WireGuard até detectar que o Discord está estável.
5. Encerra o `wireproxy`, fecha as conexões TCP antigas e muda o mesmo SOCKS5 local para conexão direta.
6. Transfere o listener direto para um auxiliar invisível.
7. Quando todos os processos do Discord são encerrados, o auxiliar fecha o listener e libera a porta automaticamente.

O UDP não é alterado.

Fechar apenas a janela normalmente mantém o Discord na bandeja. Para fechar a porta, clique com o botão direito no ícone do Discord próximo ao relógio e escolha **Sair do Discord**.

## Diagnóstico

Autoteste do auxiliar que mantém e fecha a porta:

```powershell
.\Discord-WireGuard-Auto.exe --daemon-handoff-check --no-pause
```

Se aparecer “outra instância já está em execução”, use **Sair do Discord** na bandeja, aguarde o auxiliar encerrar e tente novamente.

thank you codex
