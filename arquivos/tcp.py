import asyncio
import secrets

from tcputils import *

# Constantes da RFC 2988 para o cálculo do TimeoutInterval
ALPHA = 0.125
BETA = 0.25

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):

        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return

        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return


        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            serverSequenceNumber = secrets.randbits(32)
            
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no+1, serverSequenceNumber)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.


            conexao.enviar_syn_ack()

            if self.callback:
                self.callback(conexao)
        
        elif id_conexao in self.conexoes:

            #se a flag recebida for FIN, chamamos o metodo de fechar
            if(flags & FLAGS_FIN)== FLAGS_FIN and (payload== b''):
                self.conexoes[id_conexao].fechar(enviar_fin=False)

            else: # Passa para a conexão adequada se ela já estiver estabelecida
                self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, expected_seqno, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.expected_seqno = expected_seqno 
        self.seq_no = seq_no
        self.segmentos_nao_confirmados = []
        self.timer = None
        self.callback = None
        self.estimated_rtt = None
        self.dev_rtt = None
        self.timeout_interval = 1
        self.janela = 1  # Tamanho da janela em MSS
        self.bytes_confirmados = 0
        self.dados_pendentes = bytearray()

    def _retransmitir(self):
        """
        Callback para os segmentos que são perdidos.
        """
        # Todos segmentos confirmados
        if len(self.segmentos_nao_confirmados) == 0:
            return

        self.janela = max(1, self.janela // 2)
        self.bytes_confirmados = 0

        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        menor_seq_no = self.segmentos_nao_confirmados[0]
        # Para não usá-lo no cálculo do SampleRTT
        menor_seq_no["retransmitido"] = True

        header = make_header(dst_port, src_port, menor_seq_no["seq_no"], self.expected_seqno, FLAGS_ACK)
        segmento = fix_checksum(header+menor_seq_no["payload"], dst_addr, src_addr)

        self.servidor.rede.enviar(segmento, src_addr)
        # Reinicia o timer ainda para o segmento de menor seq_no
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._retransmitir)

    def _atualizar_timeout_interval(self, sample_rtt):
        """
        Atualiza EstimatedRTT, DevRTT e TimeoutInterval a partir de um novo SampleRTT (RFC 2988).
        """
        if self.estimated_rtt is None:
            self.estimated_rtt = sample_rtt
            self.dev_rtt = sample_rtt / 2
        else:
            self.dev_rtt = (1 - BETA) * self.dev_rtt + BETA * abs(sample_rtt - self.estimated_rtt)
            self.estimated_rtt = (1 - ALPHA) * self.estimated_rtt + ALPHA * sample_rtt

        self.timeout_interval = self.estimated_rtt + 4 * self.dev_rtt

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):

        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        # ACKs repetidos ou fora dos dados enviados não liberam a janela.
        if (flags & FLAGS_ACK and self.segmentos_nao_confirmados
                and self.segmentos_nao_confirmados[0]["seq_no"] < ack_no <= self.seq_no):
            ainda_nao_confirmados = []
            agora = asyncio.get_event_loop().time()
            sample_rtt = None
            houve_retransmissao = False
            confirmados = 0
            for elemento in self.segmentos_nao_confirmados:
                fim_segmento = elemento["seq_no"] + len(elemento["payload"])
                if ack_no < fim_segmento:
                    ainda_nao_confirmados.append(elemento)
                else:
                    confirmados += len(elemento["payload"])
                    if elemento["retransmitido"]:
                        houve_retransmissao = True
                    else:
                        sample_rtt = agora - elemento["timestamp"]
            self.segmentos_nao_confirmados = ainda_nao_confirmados

            if confirmados:
                self.bytes_confirmados += confirmados
                if self.bytes_confirmados >= self.janela * MSS:
                    self.janela += 1
                    self.bytes_confirmados = 0

                if sample_rtt is not None and not houve_retransmissao:
                    self._atualizar_timeout_interval(sample_rtt)

                if self.timer:
                    self.timer.cancel()
                    self.timer = None
                if self.segmentos_nao_confirmados:
                    self.timer = asyncio.get_event_loop().call_later(
                        self.timeout_interval, self._retransmitir)

                self._enviar_pendentes()

        if seq_no == self.expected_seqno and len(payload)>0:
            self.expected_seqno += len(payload)

            if self.callback:
                self.callback(self, payload)
            
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            header = make_header(dst_port, src_port, self.seq_no, self.expected_seqno, FLAGS_ACK)
            segmento = fix_checksum(header, dst_addr, src_addr)
            
            self.servidor.rede.enviar(segmento,src_addr)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback
    
    def enviar_syn_ack(self):
        """
        Usado somente para retornar o syn-ack na primeira resposta do servidor
        """

        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        header = make_header(dst_port, src_port, self.seq_no,
                            self.expected_seqno, FLAGS_SYN | FLAGS_ACK)
        segmento = fix_checksum(header, dst_addr, src_addr)

        self.servidor.rede.enviar(segmento, src_addr)
        self.seq_no += 1 

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        self.dados_pendentes.extend(dados)
        self._enviar_pendentes()

    def _enviar_pendentes(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        em_voo = sum(len(s["payload"]) for s in self.segmentos_nao_confirmados)
        disponivel = self.janela * MSS - em_voo

        while self.dados_pendentes and disponivel > 0:
            tamanho = min(MSS, disponivel, len(self.dados_pendentes))
            part = bytes(self.dados_pendentes[:tamanho])
            del self.dados_pendentes[:tamanho]

            header = make_header(dst_port, src_port, self.seq_no,
                                 self.expected_seqno, FLAGS_ACK)
            segmento = fix_checksum(header + part, dst_addr, src_addr)
            self.segmentos_nao_confirmados.append({
                "seq_no": self.seq_no,
                "payload": part,
                "timestamp": asyncio.get_event_loop().time(),
                "retransmitido": False,
            })
            self.seq_no += tamanho
            disponivel -= tamanho

            if self.timer is None:
                self.timer = asyncio.get_event_loop().call_later(
                    self.timeout_interval, self._retransmitir)
            self.servidor.rede.enviar(segmento, src_addr)

    def fechar(self,enviar_fin=True):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão

        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if not enviar_fin:
            self.expected_seqno += 1  # o FIN do cliente consome 1 no espaço de sequência

            if self.callback:
                    self.callback(self, b'')

            header_ack = make_header(dst_port, src_port, self.seq_no,
                                  self.expected_seqno, FLAGS_ACK)
            self.servidor.rede.enviar(fix_checksum(header_ack, dst_addr, src_addr), src_addr)

        else:

            header_fin = make_header(dst_port, src_port, self.seq_no,
                                  self.expected_seqno, FLAGS_FIN | FLAGS_ACK)
            self.servidor.rede.enviar(fix_checksum(header_fin, dst_addr, src_addr), src_addr)
            self.seq_no += 1

            del self.servidor.conexoes[self.id_conexao]

        pass
