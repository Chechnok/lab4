import ssl
import socket
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta

# Конфігураційні змінні
HOST = "localhost"
PORT = 12345
CERT_FILE = "server.crt"
KEY_FILE = "server.key"


def generate_certificates():
    """Генерація приватного ключа і самопідписаного сертифікату"""
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kyiv"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        from datetime import timezone

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))  # Використовуємо час із часовою зоною UTC
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))  # Дійсний на 365 днів
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
        print("Сертифікати згенеровано:", CERT_FILE, KEY_FILE)
    except Exception as e:
        print(f"Помилка при генерації сертифікатів: {e}")
        raise


def handle_client(conn, addr):
    """Обробка з'єднання з клієнтом"""
    print(f"Підключено клієнта: {addr}")
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data or data.lower() == "exit":
                print(f"Клієнт {addr} відключився.")
                break
            print(f"Повідомлення від {addr}: {data}")
            response = f"Сервер отримав: {data}"
            conn.send(response.encode())
    except Exception as e:
        print(f"Помилка в обробці клієнта {addr}: {e}")
    finally:
        conn.close()


def run_server():
    """Запуск сервера"""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((HOST, PORT))
            server_socket.listen(5)
            print(f"[Сервер] Запущено на {HOST}:{PORT}")

            with context.wrap_socket(server_socket, server_side=True) as tls_socket:
                while True:
                    client_conn, client_addr = tls_socket.accept()
                    threading.Thread(target=handle_client, args=(client_conn, client_addr), daemon=True).start()
    except Exception as e:
        print(f"[Сервер] Помилка: {e}")
    finally:
        print("[Сервер] Завершення роботи.")


def run_client():
    """Запуск клієнта"""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(CERT_FILE)

        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as tls_sock:
                print("[Клієнт] Підключено до сервера через SSL")
                while True:
                    message = input("Введіть повідомлення ('exit' для виходу): ")
                    tls_sock.send(message.encode())
                    if message.lower() == "exit":
                        print("[Клієнт] Завершення з'єднання.")
                        break
                    response = tls_sock.recv(1024).decode()
                    print(f"[Клієнт] Відповідь сервера: {response}")
    except Exception as e:
        print(f"[Клієнт] Помилка: {e}")
    finally:
        print("[Клієнт] Завершення клієнта.")


from multiprocessing import Process
import time

if __name__ == "__main__":
    try:
        # Генерація сертифікатів
        generate_certificates()

        # Створення процесу для запуску сервера
        server_process = Process(target=run_server, daemon=True)
        server_process.start()

        # Зачекати, щоб сервер стартував
        time.sleep(1)

        # Запуск клієнта у головному процесі
        run_client()

    except KeyboardInterrupt:
        print("\n[Головний процес] Завершення програми.")
    except Exception as e:
        print(f"[Головний процес] Непередбачена помилка: {e}")
    finally:
        # Завершення процесу сервера перед виходом
        if server_process.is_alive():
            server_process.terminate()
            server_process.join()
        print("[Головний процес] Програма завершена.")

