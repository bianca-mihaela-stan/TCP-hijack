import socket
import logging
import time
import sys
logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

port = 10020
adresa = '198.10.0.2'
server_address = (adresa, port)
mesaj = "merea"
logging.info('Handshake cu %s', str(server_address))
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
sock.connect(server_address)

while True:
    try:
        time.sleep(3)
        sock.send(mesaj.encode('utf-8'))
        logging.info('Content trimis: "%s"', mesaj)
        data = sock.recv(1024)
        logging.info('Content primit: "%s"', data)
    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        logging.info('closing socket')
        sock.close()
        exit()
