import socket, threading
def h(c,a):
    try: c.recv(1024); c.send(b'HTTP/1.1 200 OK\r\n\r\nOK')
    except: pass
    finally: c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 8000)); s.listen(500)
print('Ready on port 8000')
while True: c,a = s.accept(); threading.Thread(target=h, args=(c,a), daemon=True).start()