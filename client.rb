require 'socket'

_ip = "0.0.0.0"
_port = 1337
_buff_size = 4096
_auth = "74d521eac2deb66cb1f5c82eeff113bfd938d9a4e080f921b5a59b75e26b19fc"
_domain = "pontanegra.com.br"
_subdomains = "www.pontanegra.com.br,ofertas.pontanegra.com.br"
_send_req = "#{_auth}:#{_domain}:#{_subdomains}"

sock = TCPSocket.new _ip, _port

sock.send(_send_req, 0)
puts sock.recv(_buff_size)
sock.close