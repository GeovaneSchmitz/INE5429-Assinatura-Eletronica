# Assinatura digital e execução segura de código

Simulação didática em Python do fluxo do relatório: raiz confiável → bootloader → chave do bootloader → kernel. As assinaturas usam RSA-PSS (3072 bits) e SHA-256, pela biblioteca `cryptography`.

## Executar

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

## Limites e próximos passos

O bootloader é um componente simulado; o verificador Python realiza as etapas do fluxo, e o kernel é um programa Python demonstrativo. Isso não implementa firmware UEFI nem carrega um sistema operacional. O verificador, o interpretador e a chave raiz são pressupostos confiáveis. Trocar a raiz na linha de comando altera explicitamente a confiança da simulação.

A assinatura autentica a origem e integridade; não garante que o código seja inofensivo. `--execute` executa o kernel com as permissões do usuário. O modo `-I` do Python não constitui uma sandbox.

As chaves privadas de demonstração são armazenadas sem senha, em diretório com modo 700 e arquivos com modo 600 em sistemas POSIX. Elas não participam da verificação e não devem ser distribuídas com a imagem. A raiz em disco não oferece proteção de hardware.

Próximas etapas: comandos separados de assinatura para componentes próprios, política autenticada de revogação, proteção contra rollback e demonstração de uma cadeia com componentes executáveis independentes. PK, KEK, db e dbx ainda não são implementados.
