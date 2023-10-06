#!/usr/bin/python3

from abc import ABC, abstractmethod
import sys, argparse, logging, signal, threading
import pprint

from socketserver import ThreadingMixIn, TCPServer, BaseRequestHandler
import socket, ssl

try:
    from lumina.lumina_structs import rpc_message_parse, rpc_message_build, RPC_TYPE
    from lumina.database import LuminaDatabase
except ImportError:
    # local import for standalone use
    from lumina_structs import rpc_message_parse, rpc_message_build, RPC_TYPE
    from database import LuminaDatabase


################################################################################
#
# Protocole
#
################################################################################

class LuminaRequestHandler(BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.logger = server.logger
        self.database = server.database
        super().__init__(request, client_address, server)

    def send_rpc_message(self, code, **kwargs):
        data = rpc_message_build(code, **kwargs)
        self.logger.debug(f"sending RPC Packet ({code=}, {kwargs=}")
        self.request.send(data)

    def recv_rpc_message(self):
        packet, message = rpc_message_parse(self.request)
        self.logger.debug(f"got new RPC Packet ({packet.code=}, {message=}")
        return packet, message

    def handle(self):
        packet, message = self.recv_rpc_message()

        if packet.code != RPC_TYPE.RPC_HELO:
            self.send_rpc_message(RPC_TYPE.RPC_NOTIFY, message = 'Expected helo')
            return

        if self.server.is_blacklisted(message):
            self.send_rpc_message(RPC_TYPE.RPC_FAIL, status = 0, message = 'You are black-listed!')
            return
        
        self.send_rpc_message(RPC_TYPE.RPC_OK)

        while self.handle_rpc_message():
            pass

    def handle_rpc_message(self) ->  bool:
        try:
            packet, message = self.recv_rpc_message()
        except:
            self.logger.debug('connection has been closed.')
            return False
        
        match packet.code:
            case RPC_TYPE.PUSH_MD:
                pprint.pprint(message)
                self.send_rpc_message(RPC_TYPE.PUSH_MD_RESULT, resultsFlags=[self.database.push(info) for info in message.funcInfos])
            case RPC_TYPE.PULL_MD:
                signatures = [self.database.pull(sig) for sig in message.funcInfos]
                self.send_rpc_message(
                    RPC_TYPE.PULL_MD_RESULT,
                    found=list(map(lambda v: int(v is not None), signatures)),
                    results=list(filter(None, signatures))
                )
            case _:
                self.logger.debug("[-] ERROR: message handler not implemented")
                self.send_rpc_message(RPC_TYPE.RPC_NOTIFY, message = "Unknown command")

        return True

class BaseLuminaServer(ABC, ThreadingMixIn, TCPServer):
    def __init__(self, database, config, logger, bind_and_activate=True):
        super().__init__((config.ip, config.port), LuminaRequestHandler, bind_and_activate)
        self.config = config
        self.database = database
        self.logger = logger

    def get_request(self):
        conn, info = self.socket.accept()

        self.logger.debug(f"new client {info}")
        self.handle_connection(conn, info)

        return conn, info

    def shutdown(self, save=True):
        self.logger.info("Server stopped")
        super().shutdown()
        self.database.close(save=save)

    def serve_forever(self):
        self.logger.info(f"Server started. Listening on {self.server_address[0]}:{self.server_address[1]} (TLS={'ON' if isinstance(self, TLSLuminaServer) else 'OFF'})")
        super().serve_forever()

    def is_blacklisted(self, message):
        """
        Return True if user is authozied, else False
        """
        # check (message.hexrays_licence, message.hexrays_id, message.watermak, message.field_0x36)
        # self.logger.debug("RPC client accepted")
        self.logger.debug(f"Checking client {message.hexrays_id=}")
        # Check if id is in whitelist
        return message.hexrays_id in []

    @abstractmethod
    def handle_connection(self) -> None:
        """
        Handle request
        """

class PlainTextLuminaServer(BaseLuminaServer):
    def handle_connection(self, conn, info):
        if self.is_tls_connection(conn):
            self.logger.error("TLS client HELLO detected on plaintext mode. Check IDA configuration and cert. Aborting")
            conn.close()
            raise OSError("NO TLS")

        self.logger.debug("Starting plaintext session")
    
    @staticmethod
    def is_tls_connection(conn: socket):
        # https://tls12.xargs.org/#client-hello
        return conn.recv(2, socket.MSG_PEEK) == b'\x16\x03'


class TLSLuminaServer(BaseLuminaServer):
    def handle_connection(self, conn, info) -> None:
        self.logger.debug("Starting TLS session")
        try:
            conn = ssl.wrap_socket(conn,
                                   ssl_version = ssl.PROTOCOL_TLSv1_2,
                                   server_side = True,
                                   certfile=self.config.cert.name,
                                   keyfile=self.config.cert_key.name)

        except Exception:
            self.logger.exception("TLS connection failed. Check IDA configuration and cert")
            raise


def signal_handler(sig, frame, server):
    print('Ctrl+C caught. Exiting')
    server.shutdown(save=True)
    sys.exit(0)


def main():
    # default log handler is stdout. You can add a FileHandler or any handler you want
    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger = logging.getLogger("lumina")
    logger.addHandler(log_handler)
    logger.setLevel(logging.DEBUG)

    # Parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument("db", type=argparse.FileType('w+'), default="", help="database file")
    parser.add_argument("-i", "--ip", dest="ip", type=str, default="127.0.0.1", help="listening ip address (default: 127.0.0.1")
    parser.add_argument("-p", "--port", dest="port", type=int, default=4443, help="listening port (default: 4443")
    parser.add_argument("-c", "--cert", dest="cert", type=argparse.FileType('r'), default = None, help="proxy certfile (no cert means TLS OFF).")
    parser.add_argument("-k", "--key", dest="cert_key",type=argparse.FileType('r'), default = None, help="certificate private key")
    parser.add_argument("-l", "--log", dest="log_level", type=str, choices=["NOTSET", "DEBUG", "INFO", "WARNING"], default="INFO", help="log level bases on python logging value (default:info)")
    config = parser.parse_args()

    logger.setLevel(config.log_level)

    # create db & server
    database = LuminaDatabase(logger, config.db)
    TCPServer.allow_reuse_address = True
    start_tls_server = None not in (config.cert, config.cert_key)
    server = (TLSLuminaServer if start_tls_server else PlainTextLuminaServer)(database, config, logger)

    # set ctrl-c handler
    signal.signal(signal.SIGINT, lambda sig,frame:signal_handler(sig, frame, server))

    # start server
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = False
    server_thread.start()
    server_thread.join()

    server.database.close(save=True)

if __name__ == "__main__":
    main()