# Laboratório de Redes — Docker + TUN

## Execução

`docker compose up -d --build` — constrói a imagem e inicia o container em segundo plano.

1. `docker compose exec -T redes python3 -u exemplo_integracao_p4.py` -> inicia o servidor Echo com a pilha TCP/IP/SLIP em Python.
2. `docker compose exec -T redes python3 -u slattach_virtual.py /dev/pts/1` -> cria a interface TUN e conecta ao PTY informado pelo servidor.
3. `docker compose exec redes bash` -> abre um terminal no container.
   - `ip addr add 192.168.123.1 peer 192.168.123.2 dev tun0` -> configura o endereçamento e a rota ponto a ponto.
   - `ip link set tun0 up` -> ativa a interface.
4. `docker compose exec redes nc -v 192.168.123.2 7000` -> estabelece uma conexão TCP com o servidor.

## Conceitos

- **slattach:** associa um dispositivo serial físico ou virtual a uma interface de rede utilizando SLIP.
- **SLIP:** encapsula e delimita pacotes IP em um fluxo de bytes. Responsável pelo enquadramento dos datagramas IP
- **TUN:** interface virtual de camada 3 que permite trocar pacotes IP entre kernel e userspace.
- **PTY:** pseudoterminal que simula um canal de comunicação serial.
- **slattach_virtual.py:** ponte entre TUN e PTY, substituindo o SLIP do kernel.
- **select():** aguarda eventos de leitura em múltiplos descritores.
- **ioctl():** realiza operações de controle sobre dispositivos.
- **NET_ADMIN:** permissão para administrar interfaces e rotas de rede.

## Práticas

- **P1 — Aplicação:** IRC.
- **P2 — Transporte:** implementação do TCP.
- **P3 — Rede:** implementação do IPv4 e roteamento.
- **P4 — Enlace:** implementação do SLIP.
- **S1 — Física:** integração das camadas com as placas Zybo.

## Fluxo dos dados

Netcat → TCP Linux → IP Linux → TUN → slattach_virtual.py → PTY → SLIP → IPv4 → TCP → Servidor Echo.

## Depuração

- `ip addr show tun0` — verifica a interface.
- `ip route get 192.168.123.2` — verifica a rota.
- `ls -l /dev/pts/` — lista pseudoterminais.
- `tcpdump -i tun0 -nn -X` — inspeciona pacotes.
- `-T` — impede que o Docker aloque um PTY adicional.
- `-u` — desabilita o buffering da saída do Python.