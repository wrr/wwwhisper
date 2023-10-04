import http.server
import socketserver

PORT = 8000

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='www_static', **kwargs)


# After this script is started, JS unit test runner is available at
# http://localhost:8000/js_tests/index.html

with socketserver.TCPServer(('127.0.0.1', PORT), Handler) as httpd:
    try:
        print(f'Serving static files at port {PORT}')
        httpd.serve_forever()
    except Exception:
        httpd.shutdown()
