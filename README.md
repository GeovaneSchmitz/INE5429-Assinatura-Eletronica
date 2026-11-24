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

Na imagem recém-gerada, inspecione o registro assinado e compare seu campo `sha256` com o resumo dos bytes do kernel. Acrescente o mesmo comentário em UTF-8 usado no relatório e repita a verificação.

```bash
python3 -c 'import json; print(json.load(open("demo/image/kernel.sig.json"))["record"])'
sha256sum demo/image/kernel.py
printf '# alteração de teste\n' >> demo/image/kernel.py
sha256sum demo/image/kernel.py
python secure_boot.py boot demo/image --root-key demo/trust/root.pem --execute
```

O resumo original começa com `d5886c53` e o do arquivo editado com `dd503567`. A assinatura do manifesto continua válida. Como o segundo resumo difere do registrado, o verificador responde `BOOT BLOQUEADO: Kernel adulterado` e retorna 1. Use um diretório novo para repetir o exemplo.

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
sudo pacman -S --needed qemu-system-x86 edk2-ovmf systemd-ukify sbsigntools virt-firmware mkinitcpio cryptsetup e2fsprogs cpio openssl python-pexpect curl bzip2
```

Para reproduzir o ensaio, execute os comandos a partir da raiz deste repositório e no mesmo terminal. O arquivo `lfs83.bz2` contém um sistema de arquivos ext4. O comando `prepare-lfs` confere o SHA-256 do download, descompacta uma cópia e recupera o journal com `e2fsck`. [Release do LFS 8.3 usada no ensaio](https://github.com/EvilFreelancer/docker-lfs-build/releases/tag/8.3)

```bash
mkdir -p ~/.local/share
lab=$(mktemp -d ~/.local/share/t4-lab.XXXXXXXX)
curl -fL --output "$lab/lfs83.bz2" \
    https://github.com/EvilFreelancer/docker-lfs-build/releases/download/8.3/lfs83.bz2
vm/luks prepare-lfs "$lab/lfs83.bz2" "$lab/lfs-root.ext4"
vm/luks create "$lab/lfs-root.ext4" "$lab/vm"
vm/luks boot "$lab/vm"
```

Durante o preparo, escolha a senha de login de `ensaio`. O instalador inicia uma VM com a cópia ext4, configura a montagem de `/` pelo UUID no `/etc/fstab`, remove a entrada de swap de exemplo e cria a conta. Ao final, desmonta o ext4 e verifica o sistema de arquivos. No boot normal, a imagem EFI fornece `console=ttyS0,115200`. O SysVinit desta versão do LFS lê esse parâmetro e abre o login serial automaticamente. [Rotina de preparo no convidado](vm/prepare-root)

Durante o `create`, escolha a senha LUKS, confirme-a e digite-a uma terceira vez para copiar os dados. A imagem ext4 preparada continua em claro e é conectada somente para leitura nessa cópia. No `boot`, a primeira senha desbloqueia o disco. No prompt `login:`, entre como `ensaio` com a senha definida no preparo.

Para encerrar a demonstração com essa conta, pressione `Ctrl+a` e depois `c` para abrir o monitor QEMU. Digite `sendkey ctrl-alt-delete` e volte ao console com `Ctrl+a`, `c`. O LFS desmonta a raiz e reinicia. Quando aparecer o novo pedido da senha LUKS, pressione `Ctrl+a`, `x` para fechar o QEMU com o volume já bloqueado.

Quem já possui uma imagem raw ext4 desmontada com `/sbin/init`, login em `ttyS0` e a raiz configurada no `fstab` pode passá-la diretamente a `vm/luks create`. O provisionamento preserva o UUID do ext4 e gera outro UUID para o volume LUKS.

O kernel padrão vem de `/usr/lib/modules/$(uname -r)/vmlinuz`. Para usar o kernel compilado pelo grupo, defina `KERNEL=/caminho/para/vmlinuz` ao criar a VM e instale os módulos correspondentes em `/usr/lib/modules/<versão>` no host de construção. O kernel precisa suportar EFI stub, initramfs, console serial, VirtIO, ext4 e dm-crypt com AES-XTS. `OVMF_CODE` e `OVMF_VARS` permitem indicar outro par compatível de firmware Secure Boot e modelo de variáveis vazio. Para a demonstração, o mesmo certificado é cadastrado em PK, KEK e db na cópia do modelo usada pela VM.

### Verificar a demonstração

Com a VM desligada, execute o teste de integração. Ele usa uma cópia temporária do disco e das variáveis do firmware e pede a senha LUKS pelo terminal.

```bash
/usr/bin/python3 tests/luks_vm.py "$lab/vm"
```

| Cenário | Resultado esperado |
| --- | --- |
| Imagem EFI com a assinatura removida | OVMF recusa a execução antes do pedido de senha. |
| Mesma imagem EFI assinada com um certificado de teste ausente da base `db` | `sbverify` confirma a assinatura com o certificado externo. O OVMF recusa a imagem antes do pedido de senha. |
| Imagem assinada e senha LUKS incorreta | O volume continua fechado e o initramfs pede a senha novamente. |
| Imagem assinada e senha correta | O LFS monta a raiz e chega ao login serial. |

A primeira VM de demonstração usou o kernel Arch `7.3.4-arch1-2`. As figuras do relatório de 23/11/2026 e a reprodução dos quatro cenários usam `7.3.5-arch1-1`, com LFS 8.3 e QEMU 11.1.3. No teste, cada inicialização parte de uma nova cópia das variáveis originais do firmware. A chave externa é criada em diretório temporário, fora da partição EFI.

No host, execute `cryptsetup luksDump "$lab/vm/root.luks"` para inspecionar o volume LUKS2. No convidado, os comandos abaixo mostram o kernel, o dispositivo montado como raiz e o byte de estado do Secure Boot, após os quatro bytes de atributos da variável EFI.

```bash
uname -r
awk '$2 == "/" {print $1, $3}' /proc/mounts
od -An -j4 -N1 -tu1 /sys/firmware/efi/efivars/SecureBoot-*
```

O resultado esperado no ensaio é `/dev/mapper/t4root ext4` para a raiz e `1` para Secure Boot. A chave privada de assinatura fica no diretório `private/` do host. O LUKS2 usa Argon2id na derivação de chave. A assinatura cobre os componentes da imagem EFI. A integridade dos arquivos do ext4 após o desbloqueio está fora dessa verificação.

## Limites do simulador Python

O bootloader é um componente simulado; o verificador Python realiza as etapas do fluxo, e o kernel é um programa Python demonstrativo. Isso não implementa firmware UEFI nem carrega um sistema operacional. O verificador, o interpretador e a chave raiz são pressupostos confiáveis. Trocar a raiz na linha de comando altera explicitamente a confiança da simulação.

A assinatura autentica a origem e integridade; não garante que o código seja inofensivo. `--execute` executa o kernel com as permissões do usuário. O modo `-I` do Python não constitui uma sandbox.

As chaves privadas de demonstração são armazenadas sem senha, em diretório com modo 700 e arquivos com modo 600 em sistemas POSIX. Elas não participam da verificação e não devem ser distribuídas com a imagem. A raiz em disco não oferece proteção de hardware.

Próximas etapas: comandos separados de assinatura para componentes próprios, política autenticada de revogação, proteção contra rollback e demonstração de uma cadeia com componentes executáveis independentes. PK, KEK, db e dbx ainda não são implementados.
