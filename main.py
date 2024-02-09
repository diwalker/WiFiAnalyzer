import tkinter as tk
import threading
import scapy.all as scapy
import ctypes



class WiFiAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Analyzer")
        self.root.iconbitmap("assets/wf.ico")

        self.create_widgets()
        self.stop_refresh = threading.Event()
        self.refresh_lock = threading.Lock()
        self.scan_thread = None
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        def set_app_icon(self, icon_path):
            try:
                # Define o ícone da aplicação
                self.root.iconbitmap(default="assets/wf.ico")

                # Define o ícone da barra de tarefas
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("WiFiAnalyzer")
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(default="assets/wf.ico")

            except Exception as e:
                print(f"Error setting app icon: {e}")

    def create_widgets(self):
        # Adicionando o Frame principal
        main_frame = tk.Frame(self.root, bg="#28282B", padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.devices_text = tk.Text(main_frame, width=65, height=21, wrap=tk.NONE, bg='black', fg='white')
        self.devices_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Adicionando um Frame para o botão SCAN
        button_frame = tk.Frame(main_frame, bg="#28282B")
        button_frame.pack(pady=10)

        self.refresh_button = tk.Button(button_frame, text="SCAN", command=self.start_scan_thread, bg="#28282B",
                                        fg="white")
        self.refresh_button.pack()

    def get_devices(self):
        try:
            devices_list = []
            devices = scapy.arping("192.168.0.1/24", timeout=2, verbose=False)[0]

            for device in devices:
                ip_address = device[1].psrc
                mac_address = device[1].hwsrc
                devices_list.append({"ip": ip_address, "mac": mac_address})

            return devices_list

        except Exception as e:
            self.log_error(f"Error while getting devices: {e}")
            return []

    def refresh_devices(self):
        with self.refresh_lock:
            try:
                devices = self.get_devices()
                self.devices_text.config(state=tk.NORMAL)
                self.devices_text.delete(1.0, tk.END)

                # Apply tags for formatting
                self.devices_text.tag_configure("white", foreground="white")
                self.devices_text.tag_configure("green", foreground="green")
                self.devices_text.tag_configure("bold", font="TkFixedFont 12 bold")

                for device in devices:
                    text = f"IP: {device['ip']} MAC: {device['mac']} Conectado\n"
                    self.colorize_text(text)

                self.devices_text.insert(tk.END, f"\nTotal de Dispositivos Conectados: {len(devices)}\n", "bold")

                self.devices_text.config(state=tk.DISABLED)

                # Centralizar o texto
                self.devices_text.tag_configure("center", justify='center')
                self.devices_text.tag_add("center", "1.0", "end")

            except Exception as e:
                self.log_error(f"Error refreshing devices: {e}")

    def colorize_text(self, text):
        self.devices_text.insert(tk.END, text, "white")

        # Colorir palavras-chave específicas em verde
        keywords = ["IP:", "MAC:", "Conectado"]
        for keyword in keywords:
            start_index = "1.0"
            while True:
                start_index = self.devices_text.search(keyword, start_index, tk.END)
                if not start_index:
                    break
                end_index = f"{start_index}+{len(keyword)}c"
                self.devices_text.tag_add("green", start_index, end_index)
                self.devices_text.tag_add("bold", start_index, end_index)
                start_index = end_index

    def start_scan_thread(self):
        if self.scan_thread is None or not self.scan_thread.is_alive():
            self.scan_thread = threading.Thread(target=self.scan_devices)
            self.scan_thread.start()

    def scan_devices(self):
        while not self.stop_refresh.is_set():
            self.refresh_devices()
            self.stop_refresh.wait(5)  # Aguarde 5 segundos antes de iniciar uma nova varredura

    def on_close(self):
        self.stop_refresh.set()
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join()
        self.root.destroy()

    def log_error(self, message):
        print(message)
        if self.devices_text:
            self.devices_text.config(state=tk.NORMAL)
            self.devices_text.insert(tk.END, f"Error: {message}\n", "white")
            self.devices_text.config(state=tk.DISABLED)


if __name__ == "__main__":
    try:
        root = tk.Tk()
        root.configure(bg="#28282B")
        analyzer = WiFiAnalyzer(root)
        print("Tkinter mainloop starting...")
        root.mainloop()
        print("Tkinter mainloop ended.")
    except Exception as e:
        print(f"Error while running the program: {e}")
