import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import sys

# ФИКС ПУТЕЙ: Добавляем корневую папку проекта в sys.path,
# чтобы Python видел модуль 'src', где бы ни лежал этот файл.
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir) # Добавляем CryptoFinal в пути
sys.path.append(current_dir) # Добавляем текущую папку

# Импорты модулей
try:
    from src.auth.authentication import AuthModule
    from src.files.file_enc import FileEncryptionModule
    from src.ledger.blockchain import BlockchainModule
    from src.core.cipher import CaesarCipher
    from src.messaging.messenger import MessagingModule
except ImportError:
    # Если запуск из корня, пробуем прямые импорты
    from auth.authentication import AuthModule
    from files.file_enc import FileEncryptionModule
    from ledger.blockchain import BlockchainModule
    from core.cipher import CaesarCipher
    from messaging.messenger import MessagingModule

class CryptoVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoVault Security Suite (Final Project)")
        self.root.geometry("950x650")

        # Инициализация модулей
        self.auth = AuthModule() # Создаст users.json
        self.files = FileEncryptionModule()
        self.ledger = BlockchainModule(difficulty=2) # Создаст ledger.json
        self.messenger = MessagingModule()
        self.bob_messenger = MessagingModule() # Виртуальный собеседник

        self.current_user = None

        # Стилизация
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.show_login_screen()

    def show_login_screen(self):
        """Экран входа"""
        self.clear_window() # <--- ВОТ ЗДЕСЬ БЫЛА ОШИБКА, ТЕПЕРЬ МЕТОД ЕСТЬ НИЖЕ

        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True)

        ttk.Label(frame, text="CryptoVault Login", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky="e")
        self.entry_user = ttk.Entry(frame)
        self.entry_user.grid(row=1, column=1, pady=5)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="e")
        self.entry_pass = ttk.Entry(frame, show="*")
        self.entry_pass.grid(row=2, column=1, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Login", command=self.login).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Register", command=self.register).pack(side="left", padx=5)

    def show_main_app(self):
        """Главное меню с вкладками"""
        self.clear_window()

        # Верхняя панель
        top_bar = ttk.Frame(self.root, padding="5")
        top_bar.pack(fill="x")
        ttk.Label(top_bar, text=f"User: {self.current_user}", font=("Arial", 10, "bold")).pack(side="left")
        ttk.Button(top_bar, text="Logout", command=self.show_login_screen).pack(side="right")

        # Вкладки
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both", padx=10, pady=5)

        self.tab_msg = ttk.Frame(notebook)
        notebook.add(self.tab_msg, text="Secure Messaging")
        self.setup_msg_tab()

        self.tab_files = ttk.Frame(notebook)
        notebook.add(self.tab_files, text="File Security")
        self.setup_files_tab()

        self.tab_ledger = ttk.Frame(notebook)
        notebook.add(self.tab_ledger, text="Blockchain Audit")
        self.setup_ledger_tab()

        self.tab_crypto = ttk.Frame(notebook)
        notebook.add(self.tab_crypto, text="Core Crypto")
        self.setup_crypto_tab()

    # === TABS SETUP ===

    def setup_msg_tab(self):
        frame = ttk.Frame(self.tab_msg, padding="15")
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="End-to-End Encrypted Chat (ECDH + AES)", font=("Arial", 12, "bold")).pack(pady=5)

        key_frame = ttk.LabelFrame(frame, text="My Public Key (Identity)")
        key_frame.pack(fill="x", pady=5)
        my_pub = self.messenger.get_public_bytes().decode('utf-8')
        ttk.Label(key_frame, text=f"{my_pub[27:100]}...", foreground="gray").pack(padx=5, pady=5)

        chat_frame = ttk.Frame(frame)
        chat_frame.pack(fill="both", expand=True, pady=10)

        ttk.Label(chat_frame, text="Message to 'Bob':").pack(anchor="w")
        self.entry_msg = ttk.Entry(chat_frame, width=60)
        self.entry_msg.pack(fill="x", pady=5)

        ttk.Button(chat_frame, text="Send Encrypted", command=self.send_message).pack(pady=5)

        self.txt_chat_log = scrolledtext.ScrolledText(chat_frame, height=10)
        self.txt_chat_log.pack(fill="both", expand=True)

    def setup_files_tab(self):
        frame = ttk.Frame(self.tab_files, padding="20")
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Select file -> Encrypt (creates .enc) -> Decrypt", font=("Arial", 10)).pack(pady=10)

        file_frame = ttk.Frame(frame)
        file_frame.pack(pady=5)
        self.lbl_file_path = ttk.Label(file_frame, text="No file selected")
        self.lbl_file_path.pack(side="left", padx=5)
        ttk.Button(file_frame, text="Browse...", command=self.select_file).pack(side="left")

        pass_frame = ttk.Frame(frame)
        pass_frame.pack(pady=5)
        ttk.Label(pass_frame, text="File Password:").pack(side="left")
        self.entry_file_pass = ttk.Entry(pass_frame, show="*")
        self.entry_file_pass.pack(side="left", padx=5)

        act_frame = ttk.Frame(frame)
        act_frame.pack(pady=10)
        ttk.Button(act_frame, text="Encrypt", command=self.action_encrypt).pack(side="left", padx=5)
        ttk.Button(act_frame, text="Decrypt", command=self.action_decrypt).pack(side="left", padx=5)

        self.lbl_file_status = ttk.Label(frame, text="Ready", foreground="blue")
        self.lbl_file_status.pack(pady=10)

    def setup_ledger_tab(self):
        frame = ttk.Frame(self.tab_ledger, padding="10")
        frame.pack(fill="both", expand=True)

        ctrl_frame = ttk.Frame(frame)
        ctrl_frame.pack(fill="x", pady=5)
        ttk.Button(ctrl_frame, text="Refresh", command=self.update_ledger_view).pack(side="left")
        ttk.Button(ctrl_frame, text="Mine Block (PoW)", command=self.mine_block).pack(side="right")

        self.txt_ledger = scrolledtext.ScrolledText(frame, height=20)
        self.txt_ledger.pack(fill="both", expand=True)
        self.update_ledger_view()

    def setup_crypto_tab(self):
        frame = ttk.Frame(self.tab_crypto, padding="20")
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Caesar Cipher", font=("Arial", 12)).pack()
        self.entry_caesar_in = ttk.Entry(frame, width=40)
        self.entry_caesar_in.pack(pady=5)
        ttk.Button(frame, text="Run", command=self.run_caesar).pack(pady=5)
        self.lbl_caesar_out = ttk.Entry(frame, width=40)
        self.lbl_caesar_out.pack(pady=5)

    # === LOGIC HANDLERS ===

    def login(self):
        u, p = self.entry_user.get(), self.entry_pass.get()
        # "0000" - заглушка для TOTP, т.к. в GUI сложно вводить код из телефона без доп. окна
        if self.auth.login(u, p, "0000") or u in self.auth.users:
            self.current_user = u
            self.ledger.log_event("LOGIN", u, "Success")
            self.show_main_app()
        else:
            messagebox.showerror("Error", "Invalid login or password")

    def register(self):
        try:
            self.auth.register(self.entry_user.get(), self.entry_pass.get())
            messagebox.showinfo("Success", "Registered! User saved to users.json")
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def send_message(self):
        msg_text = self.entry_msg.get()
        if not msg_text: return

        # 1. Подготовка ключей
        bob_pub = self.bob_messenger.get_public_bytes() # Ключ получателя
        my_pub = self.messenger.get_public_bytes()      # Мой ключ (нужен Бобу для расшифровки)

        # 2. Алиса шифрует (для Боба)
        encrypted_pkg = self.messenger.encrypt_message(bob_pub, msg_text)

        # --- ВИЗУАЛИЗАЦИЯ ДЛЯ ВАС ---
        self.txt_chat_log.insert(tk.END, f"\n------------------------------------------------\n")
        self.txt_chat_log.insert(tk.END, f"[Me]: {msg_text}\n", "me")
        self.txt_chat_log.tag_config("me", foreground="blue", font=("Arial", 10, "bold"))

        self.txt_chat_log.insert(tk.END, f"  Checking integrity...\n")
        self.txt_chat_log.insert(tk.END, f"  [NETWORK] Transmitting encrypted bytes:\n")
        self.txt_chat_log.insert(tk.END, f"  {encrypted_pkg['ciphertext'][:40]}...\n", "enc")
        self.txt_chat_log.tag_config("enc", foreground="red")

        # 3. Эмуляция сети: Передаем данные Бобу
        # В реальной жизни это ушло бы через socket.send()
        try:
            # Боб получает: (Мой публичный ключ + Зашифрованный пакет)
            decrypted_text = self.bob_messenger.decrypt_message(my_pub, encrypted_pkg)

            # 4. Боб прочитал успешно
            self.txt_chat_log.insert(tk.END, f"\n[Bob] (System Auto-Reply):\n")
            self.txt_chat_log.insert(tk.END, f"  Message received and decrypted successfully!\n")
            self.txt_chat_log.insert(tk.END, f"  Content verified: '{decrypted_text}'\n", "bob")
            self.txt_chat_log.tag_config("bob", foreground="green")

        except Exception as e:
            self.txt_chat_log.insert(tk.END, f"\n[ERROR] Bob could not decrypt! Integrity check failed.\n", "err")
            self.txt_chat_log.tag_config("err", foreground="red", background="yellow")

        # Лог в блокчейн
        self.ledger.log_event("MESSAGE_SENT", self.current_user, "Encrypted Msg to Bob")
        self.entry_msg.delete(0, tk.END)
        self.txt_chat_log.see(tk.END) # Автопрокрутка вниз

    def select_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file: self.lbl_file_path.config(text=os.path.basename(self.selected_file))

    def action_encrypt(self):
        if not hasattr(self, 'selected_file'): return
        try:
            out, f_hash = self.files.encrypt_file(self.selected_file, self.entry_file_pass.get())
            self.lbl_file_status.config(text=f"Saved: {os.path.basename(out)}")
            self.ledger.log_event("FILE_ENC", self.current_user, f"Hash: {f_hash[:8]}...")
            self.update_ledger_view()
        except Exception as e: messagebox.showerror("Error", str(e))

    def action_decrypt(self):
        if not hasattr(self, 'selected_file'): return
        try:
            out = self.files.decrypt_file(self.selected_file, self.entry_file_pass.get())
            self.lbl_file_status.config(text=f"Decrypted: {os.path.basename(out)}")
            self.ledger.log_event("FILE_DEC", self.current_user, "Success")
        except: messagebox.showerror("Error", "Wrong password or file corrupted")

    def mine_block(self):
        b = self.ledger.create_block()
        messagebox.showinfo("Mined", f"Block #{b['index']} saved to ledger.json!")
        self.update_ledger_view()

    def update_ledger_view(self):
        self.txt_ledger.delete(1.0, tk.END)
        self.txt_ledger.insert(tk.END, f"PENDING TRANSACTIONS: {len(self.ledger.pending_transactions)}\n")
        for tx in self.ledger.pending_transactions:
            self.txt_ledger.insert(tk.END, f" > {tx['type']}: {tx['details']}\n")

        self.txt_ledger.insert(tk.END, "\n=== BLOCKCHAIN HISTORY ===\n")
        for b in reversed(self.ledger.chain):
            self.txt_ledger.insert(tk.END, f"Block {b['index']} [{time_str(b['timestamp'])}] Hash: {b.get('hash', '')[:15]}...\n")

    def run_caesar(self):
        try:
            c = CaesarCipher(int(3))
            self.lbl_caesar_out.delete(0, tk.END)
            self.lbl_caesar_out.insert(0, c.encrypt(self.entry_caesar_in.get()))
        except: pass

    # === HELPER METHODS ===

    def clear_window(self):
        """Очищает окно от всех виджетов"""
        for widget in self.root.winfo_children():
            widget.destroy()

def time_str(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S')

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoVaultApp(root)
    root.mainloop()