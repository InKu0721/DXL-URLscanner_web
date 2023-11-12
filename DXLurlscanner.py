import socket
import concurrent.futures
import ipaddress
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__, static_folder='static')

class URLScanner:
    def __init__(self):
        self.result = ""

    def clean_url(self, url):
        if url.startswith("http://"):
            url = url[7:]
        elif url.startswith("https://"):
            url = url[8:]
        return url

    def get_ip_address(self, url):
        try:
            ip = ipaddress.ip_address(url)
            return str(ip)
        except ValueError:
            try:
                ip_address = socket.gethostbyname(url)
                return ip_address
            except socket.gaierror:
                return f"无法解析主机: {url}"

    def scan_port(self, ip_address, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    return port
        except socket.error as e:
            pass
        return None

    def scan_ports(self, ip_address, num_threads, min_port, max_port):
        open_ports = []
        ports_to_scan = range(min_port, max_port + 1)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(self.scan_port, ip_address, port) for port in ports_to_scan]
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
                # 在这里你也可以添加进度信息的更新，但需要更改为异步方式

        return open_ports

    def get_service_name(self, port):
        try:
            service_name = socket.getservbyport(port)
            return service_name
        except OSError:
            return "Unknown"

    def scan_url(self, url, num_threads, min_port, max_port):
        url = self.clean_url(url)
        host_name = url.split('/')[0]
        ip_address = self.get_ip_address(host_name)

        if "无法解析主机" in ip_address:
            self.result = ip_address
        else:
            open_ports = self.scan_ports(ip_address, num_threads, min_port, max_port)

            if open_ports:
                self.result = f"{host_name}的IP地址：{ip_address}\n开放的端口：\n"
                for port in open_ports:
                    service_name = self.get_service_name(port)
                    self.result += f"端口 {port}（{service_name}）是开放的\n"
            else:
                self.result = f"{host_name}的IP地址：{ip_address}\n未找到开放的端口"

url_scanner = URLScanner()

@app.route('/')
def index():
    return render_template('index.html', result=url_scanner.result)

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    num_threads = int(request.form['num_threads'])
    min_port = int(request.form['min_port'])
    max_port = int(request.form['max_port'])

    # 执行扫描并更新结果
    url_scanner.scan_url(url, num_threads, min_port, max_port)

    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
