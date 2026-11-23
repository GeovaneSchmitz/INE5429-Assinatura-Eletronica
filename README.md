# Assinatura digital e execução segura de código

O simulador Python reproduz a cadeia de confiança do relatório com RSA-PSS (3072 bits) e SHA-256. A VM demonstra o fluxo com firmware UEFI, uma imagem EFI assinada e um Linux com a raiz cifrada por LUKS2.

## Executar o simulador Python

Requer Python 3.10 ou superior.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python secure_boot.py init demo
python secure_boot.py boot demo/image --root-key demo/trust/root.pem
python secure_boot.py boot demo/image --root-key demo/trust/root.pem --execute
```

`init` exige um diretório de destino inexistente. Ele gera duas chaves privadas, a chave pública raiz confiável, os componentes e seus manifestos assinados. `boot` retorna 0 quando toda a cadeia é válida e 1 quando há falha. Com `--execute`, retorna o código de saída do kernel após autorizar o boot.

## Demonstrar adulteração

Depois de executar o caso válido:

```bash
printf '\n# alteração não assinada\n' >> demo/image/kernel.py
python secure_boot.py boot demo/image --root-key demo/trust/root.pem --execute
```

Resultado esperado: `BOOT BLOQUEADO: Kernel adulterado`; o kernel não é executado. Gere outra demonstração em um novo diretório para restaurar o cenário válido.

## Cadeia de confiança

1. O verificador recebe uma chave pública raiz por um caminho confiável, separado da imagem.
2. A raiz verifica o manifesto do bootloader, que inclui o hash do componente e o hash da chave pública autorizada a verificar o kernel.
3. O verificador compara os hashes do bootloader e dessa chave com o manifesto autenticado.
4. A chave do bootloader verifica o manifesto do kernel e o verificador compara o hash do kernel.
5. Somente após essas etapas o boot é autorizado. A execução opcional utiliza os bytes já verificados, sem reler o arquivo.

Os manifestos incluem versão e papel do componente, protegidos pela assinatura. A representação assinada é JSON canônico definido neste projeto. As assinaturas ficam em arquivos separados dos componentes.

## Testes

```bash
python3 -m unittest discover -s tests -v
```

Os testes cobrem a cadeia válida, componentes adulterados, troca de chaves, assinaturas corrompidas, arquivos ausentes e bloqueio de execução.

## VM Linux com Secure Boot e raiz LUKS2

O firmware OVMF verifica a imagem EFI assinada antes de iniciar o kernel. A imagem reúne o kernel, o initramfs e os parâmetros de boot. O initramfs identifica o disco pelo UUID do LUKS, pede a senha no console serial e monta o ext4 desbloqueado como `/`. O login e os programas vêm do sistema instalado nesse ext4.

### Criar uma VM

No Arch Linux x86_64, as ferramentas usadas são dos pacotes abaixo. O provisionamento roda como usuário comum.

```bash
sudo pacman -S --needed qemu-system-x86 edk2-ovmf systemd-ukify sbsigntools virt-firmware mkinitcpio cryptsetup e2fsprogs cpio openssl python-pexpect
```

Use uma imagem raw de um sistema de arquivos ext4 **desmontado**, com o LFS já instalado, `/sbin/init` e login em `ttyS0`. Se partir de um disco particionado, use uma cópia da partição raiz. O UUID do ext4 é preservado, por isso a entrada de `/` no `fstab` pode usar o mesmo `UUID=...`. O volume LUKS receberá um UUID próprio.

```bash
mkdir -p ~/.local/share
vm/luks create ./lfs-root.ext4 ~/.local/share/t4-lfs
vm/luks boot ~/.local/share/t4-lfs
```

O destino deve ser novo. Na criação, escolha a senha LUKS, confirme-a e digite-a uma terceira vez na VM que copia o ext4. A imagem ext4 de origem continua em claro e é conectada somente para leitura. Em cada boot, a primeira senha desbloqueia o disco. Em seguida, use uma conta do próprio LFS para entrar. Para encerrar, execute `poweroff` dentro do convidado.

O kernel padrão vem de `/usr/lib/modules/$(uname -r)/vmlinuz`. Para usar o kernel compilado pelo grupo, defina `KERNEL=/caminho/para/vmlinuz` ao criar a VM e instale os módulos correspondentes em `/usr/lib/modules/<versão>` no host de construção. O kernel precisa suportar EFI stub, initramfs, console serial, VirtIO, ext4 e dm-crypt com AES-XTS. `OVMF_CODE` e `OVMF_VARS` permitem indicar outro par compatível de firmware Secure Boot e modelo de variáveis vazio. Para a demonstração, o mesmo certificado é cadastrado em PK, KEK e db na cópia do modelo usada pela VM.

### Verificar a demonstração

Com a VM desligada, execute o teste de integração. Ele usa uma cópia temporária do disco e das variáveis do firmware e pede a senha LUKS pelo terminal.

```bash
python3 tests/luks_vm.py ~/.local/share/t4-lfs
```

| Cenário | Resultado esperado |
| --- | --- |
| Imagem EFI com a assinatura removida | OVMF recusa a execução antes do pedido de senha. |
| Imagem assinada e senha LUKS incorreta | O volume continua fechado e o initramfs pede a senha novamente. |
| Imagem assinada e senha correta | O LFS monta a raiz e chega ao login serial. |

A VM de demonstração foi testada com a raiz pré-compilada do LFS 8.3, adaptada para console serial e para montar `/` pelo UUID do ext4, e com o kernel 7.3.4 do Arch Linux. Após o login, o convidado informou `SecureBoot=1` e `/dev/mapper/t4root ext4` para a raiz. [Origem da imagem de demonstração](https://github.com/EvilFreelancer/docker-lfs-build/releases/tag/8.3)

Para inspecionar o disco no host, execute `cryptsetup luksDump ~/.local/share/t4-lfs/root.luks`. Dentro da VM, `awk '$2 == "/" {print $1, $3}' /proc/mounts` mostra a origem e o tipo da raiz. A imagem EFI fica na partição de boot legível pelo firmware. A chave privada de assinatura fica no diretório `private/` do host, fora dos discos apresentados à VM. O volume usa LUKS2 com Argon2id para proteger os dados em repouso. A assinatura cobre os componentes da imagem EFI. A integridade dos arquivos da raiz após o desbloqueio está fora dessa verificação.

## Limites do simulador Python

O bootloader é um componente simulado; o verificador Python realiza as etapas do fluxo, e o kernel é um programa Python demonstrativo. Isso não implementa firmware UEFI nem carrega um sistema operacional. O verificador, o interpretador e a chave raiz são pressupostos confiáveis. Trocar a raiz na linha de comando altera explicitamente a confiança da simulação.

A assinatura autentica a origem e integridade; não garante que o código seja inofensivo. `--execute` executa o kernel com as permissões do usuário. O modo `-I` do Python não constitui uma sandbox.

As chaves privadas de demonstração são armazenadas sem senha, em diretório com modo 700 e arquivos com modo 600 em sistemas POSIX. Elas não participam da verificação e não devem ser distribuídas com a imagem. A raiz em disco não oferece proteção de hardware.

Próximas etapas: comandos separados de assinatura para componentes próprios, política autenticada de revogação, proteção contra rollback e demonstração de uma cadeia com componentes executáveis independentes. PK, KEK, db e dbx ainda não são implementados.
