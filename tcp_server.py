import socket
import logging
import time

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10020
adresa = '0.0.0.0'
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s si portnul portul %d", adresa, port)
sock.listen(5)
conexiune = None
while conexiune == None:
    logging.info('Asteptam conexiui...')
    conexiune, address = sock.accept()
    logging.info("Handshake cu %s", address)

while True:
    try:
        data = conexiune.recv(1024)
        logging.info('Content primit: "%s"', data)
        logging.info(b"Server a primit mesajul: " + data)
        conexiune.send(b"Server a primit mesajul: " + data)
    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        logging.info('closing socket')
        conexiune.close()
        sock.close()
        exit()

