import os
import fcntl
import struct
import select
import sys
import tty
import socket
import termios

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD


def criar_tun():
    fd = os.open("/dev/net/tun", os.O_RDWR)

    ifr = struct.pack(
        "16sH22x",
        b"tun0",
        IFF_TUN | IFF_NO_PI
    )

    fcntl.ioctl(fd, TUNSETIFF, ifr)

    return fd


def slip_encode(packet):
    packet = packet.replace(
        b"\xdb", b"\xdb\xdd"
    )

    packet = packet.replace(
        b"\xc0", b"\xdb\xdc"
    )

    return b"\xc0" + packet + b"\xc0"


def slip_decode(frame):
    packet = bytearray()
    escape = False

    for byte in frame:
        if escape:
            if byte == SLIP_ESC_END:
                packet.append(SLIP_END)

            elif byte == SLIP_ESC_ESC:
                packet.append(SLIP_ESC)

            else:
                raise ValueError("Escape SLIP inválido")

            escape = False

        elif byte == SLIP_ESC:
            escape = True

        else:
            packet.append(byte)

    if escape:
        raise ValueError("Escape SLIP incompleto")

    return bytes(packet)


def escrever_serial(fd, dados):
    while dados:
        enviados = os.write(fd, dados)

        if enviados == 0:
            raise OSError("Falha na escrita serial")

        dados = dados[enviados:]


def log_packet(prefixo, packet):
    print(f"\n[{prefixo}] {len(packet)} bytes")

    if len(packet) >= 20 and packet[0] >> 4 == 4:
        origem = socket.inet_ntoa(packet[12:16])
        destino = socket.inet_ntoa(packet[16:20])
        protocolo = packet[9]
        ttl = packet[8]

        print(f"  Origem:    {origem}")
        print(f"  Destino:   {destino}")
        print(f"  Protocolo: {protocolo}")
        print(f"  TTL:       {ttl}")

        ihl = (packet[0] & 0x0F) * 4

        if protocolo == 6 and ihl >= 20 and len(packet) >= ihl + 20:
            porta_origem, porta_destino = struct.unpack(
                "!HH",
                packet[ihl:ihl + 4]
            )

            flags = packet[ihl + 13]

            print(f"  Porta origem:  {porta_origem}")
            print(f"  Porta destino: {porta_destino}")
            print(f"  Flags TCP:     0x{flags:02x}")

    print(f"  HEX: {packet.hex(' ')}", flush=True)


def main():
    if len(sys.argv) != 2:
        print("Uso: python3 slattach_virtual.py /dev/pts/N")
        sys.exit(1)

    serial_path = sys.argv[1]

    tun_fd = None
    serial_fd = None
    serial_config = None

    buffer = bytearray()

    try:
        tun_fd = criar_tun()

        print("[INIT] Interface tun0 criada.")
        print(f"[INIT] TUN FD: {tun_fd}")
        print(f"[INIT] Abrindo serial: {serial_path}")

        serial_fd = os.open(
            serial_path,
            os.O_RDWR | os.O_NOCTTY
        )

        serial_config = termios.tcgetattr(serial_fd)
        tty.setraw(serial_fd)

        print(f"[INIT] Serial FD: {serial_fd}")
        print("[INIT] Serial configurada em RAW mode.")
        print("[INIT] Aguardando pacotes...", flush=True)

        while True:
            leitores, _, _ = select.select(
                [tun_fd, serial_fd],
                [],
                []
            )

            # TUN -> SLIP -> SERIAL
            if tun_fd in leitores:
                packet = os.read(tun_fd, 65535)

                if len(packet) >= 20 and packet[0] >> 4 == 4:
                    log_packet("TUN RX", packet)

                    frame = slip_encode(packet)

                    print(f"[SLIP TX] {len(frame)} bytes")
                    print(f"  HEX: {frame.hex(' ')}")

                    escrever_serial(serial_fd, frame)

                    print("[SERIAL TX] Envio concluído.", flush=True)

                else:
                    print("[TUN RX] Pacote não IPv4 ou inválido.")

            # SERIAL -> SLIP -> TUN
            if serial_fd in leitores:
                dados = os.read(serial_fd, 4096)

                if not dados:
                    print("[SERIAL RX] Conexão encerrada.")
                    break

                print(f"\n[SERIAL RX] {len(dados)} bytes")
                print(f"  HEX: {dados.hex(' ')}", flush=True)

                for byte in dados:
                    if byte == SLIP_END:
                        if not buffer:
                            continue

                        frame = bytes(buffer)
                        buffer.clear()

                        print(f"[SLIP RX] Quadro completo: {len(frame)} bytes")

                        try:
                            packet = slip_decode(frame)

                        except ValueError as erro:
                            print(f"[SLIP ERROR] {erro}")
                            continue

                        if len(packet) >= 20 and packet[0] >> 4 == 4:
                            log_packet("SLIP DECODE", packet)

                            enviados = os.write(tun_fd, packet)

                            if enviados != len(packet):
                                print("[TUN ERROR] Escrita incompleta.")

                            else:
                                print(f"[TUN TX] {enviados} bytes injetados.",
                                      flush=True)

                        else:
                            print("[SLIP ERROR] Pacote IPv4 inválido.")

                    else:
                        buffer.append(byte)

    except KeyboardInterrupt:
        print("\n[STOP] Encerrando adaptador.")

    except OSError as erro:
        print(f"\n[ERROR] {erro}")

    finally:
        if serial_fd is not None:
            if serial_config is not None:
                try:
                    termios.tcsetattr(
                        serial_fd,
                        termios.TCSANOW,
                        serial_config
                    )
                except OSError:
                    pass

            os.close(serial_fd)

        if tun_fd is not None:
            os.close(tun_fd)

        print("[STOP] Descritores fechados.")


if __name__ == "__main__":
    main()