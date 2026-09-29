import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import multiprocessing
from multiprocessing import Process, Queue, Event
import queue
import string
import itertools
import time
from pypdf import PdfReader

def worker(pdf_path, task_queue, res_queue, prog_queue, s_event):
    try:
        reader = PdfReader(pdf_path)
        while not s_event.is_set():
            try:
                batch = task_queue.get(timeout=1)
            except Exception:
                continue
            if batch == 'STOP':
                break

            count = 0
            for pwd in batch:
                if s_event.is_set():
                    break
                try:
                    if reader.decrypt(pwd) != 0:
                        res_queue.put(pwd)
                        s_event.set()
                        return
                except Exception:
                    pass
                count += 1
            prog_queue.put(count)
    except Exception:
        pass

def password_generator(char_set, length, prefix):
    for p in itertools.product(char_set, repeat=length):
        yield prefix + "".join(p)

def recovery_manager(pdf_path, char_set, length, prefix, result_queue, progress_queue, stop_event, total_passwords):
    num_workers = multiprocessing.cpu_count()
    gen = password_generator(char_set, length, prefix)
    chunk_size = 500
    task_queue = Queue(maxsize=100)

    workers = []
    for _ in range(num_workers):
        p = Process(target=worker, args=(pdf_path, task_queue, result_queue, progress_queue, stop_event))
        p.start()
        workers.append(p)

    try:
        batch = []
        for pwd in gen:
            if stop_event.is_set():
                break
            batch.append(pwd)
            if len(batch) >= chunk_size:
                while not stop_event.is_set():
                    try:
                        task_queue.put(batch, timeout=1)
                        break
                    except queue.Full:
                        pass
                    except Exception:
                        break
                batch = []

        if batch and not stop_event.is_set():
            while not stop_event.is_set():
                try:
                    task_queue.put(batch, timeout=1)
                    break
                except queue.Full:
                    pass
                except Exception:
                    break

    except Exception as e:
        print(f"Error in manager: {e}")

    for _ in range(num_workers):
        try:
            task_queue.put('STOP', timeout=1)
        except Exception:
            pass

    for p in workers:
        p.join()

class PDFRecoveryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Key Recovery Utility")
        self.root.geometry("600x600")

        self.pdf_path = tk.StringVar()
        self.char_set_type = tk.StringVar(value="numeric")
        self.pwd_length = tk.IntVar(value=4)
        self.pwd_prefix = tk.StringVar(value="")

        self.is_running = False
        self.manager_process = None
        self.stop_event = None
        self.result_queue = None
        self.progress_queue = None

        self.total_attempts = 0
        self.start_time = 0
        self.total_passwords = 0

        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        if self.is_running:
            self.stop_recovery()
        self.root.destroy()

    def create_widgets(self):
        # File selection
        frame_file = ttk.LabelFrame(self.root, text="Target PDF File")
        frame_file.pack(fill="x", padx=10, pady=5)

        ttk.Entry(frame_file, textvariable=self.pdf_path, state="readonly").pack(side="left", fill="x", expand=True, padx=5, pady=5)
        ttk.Button(frame_file, text="Browse...", command=self.browse_file).pack(side="right", padx=5, pady=5)

        # Inspector
        self.frame_inspector = ttk.LabelFrame(self.root, text="Metadata & Security Inspector")
        self.frame_inspector.pack(fill="x", padx=10, pady=5)

        self.txt_inspector = tk.Text(self.frame_inspector, height=6, state="disabled", bg="#f0f0f0")
        self.txt_inspector.pack(fill="x", padx=5, pady=5)

        # Settings
        frame_settings = ttk.LabelFrame(self.root, text="Key Pattern & Composition")
        frame_settings.pack(fill="x", padx=10, pady=5)

        # Charsets
        frame_charset = ttk.Frame(frame_settings)
        frame_charset.pack(fill="x", padx=5, pady=2)
        ttk.Label(frame_charset, text="Character Set:").pack(side="left")
        ttk.Radiobutton(frame_charset, text="Numerical (0-9)", variable=self.char_set_type, value="numeric").pack(side="left", padx=5)
        ttk.Radiobutton(frame_charset, text="Alphanumeric", variable=self.char_set_type, value="alphanumeric").pack(side="left", padx=5)
        ttk.Radiobutton(frame_charset, text="Alpha + Symbols", variable=self.char_set_type, value="all").pack(side="left", padx=5)

        # Length
        frame_length = ttk.Frame(frame_settings)
        frame_length.pack(fill="x", padx=5, pady=2)
        ttk.Label(frame_length, text="Generated Length:").pack(side="left")
        ttk.Spinbox(frame_length, from_=1, to=20, textvariable=self.pwd_length, width=5).pack(side="left", padx=5)

        # Prefix
        frame_prefix = ttk.Frame(frame_settings)
        frame_prefix.pack(fill="x", padx=5, pady=2)
        ttk.Label(frame_prefix, text="Known Prefix (Optional):").pack(side="left")
        ttk.Entry(frame_prefix, textvariable=self.pwd_prefix).pack(side="left", padx=5, fill="x", expand=True)

        # Status
        self.frame_status = ttk.LabelFrame(self.root, text="Status & Progress")
        self.frame_status.pack(fill="both", expand=True, padx=10, pady=5)

        self.lbl_status = ttk.Label(self.frame_status, text="Ready")
        self.lbl_status.pack(anchor="w", padx=5, pady=2)

        self.progress_var = tk.DoubleVar()
        self.progressbar = ttk.Progressbar(self.frame_status, variable=self.progress_var, maximum=100)
        self.progressbar.pack(fill="x", padx=5, pady=5)

        self.lbl_stats = ttk.Label(self.frame_status, text="0 attempts | 0 attempts/sec | 0.00%")
        self.lbl_stats.pack(anchor="w", padx=5, pady=2)

        # Action Buttons
        frame_actions = ttk.Frame(self.root)
        frame_actions.pack(fill="x", padx=10, pady=10)

        self.btn_start = ttk.Button(frame_actions, text="Start Recovery", command=self.start_recovery)
        self.btn_start.pack(side="left", expand=True, fill="x", padx=5)

        self.btn_stop = ttk.Button(frame_actions, text="Stop", command=self.stop_recovery, state="disabled")
        self.btn_stop.pack(side="right", expand=True, fill="x", padx=5)

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if filename:
            self.pdf_path.set(filename)
            self.inspect_pdf(filename)

    def inspect_pdf(self, path):
        self.txt_inspector.config(state="normal")
        self.txt_inspector.delete(1.0, tk.END)

        try:
            reader = PdfReader(path)

            inspector_text = []
            inspector_text.append(f"Encrypted: {reader.is_encrypted}")

            # Metadata
            try:
                metadata = reader.metadata
                if metadata:
                    inspector_text.append("--- Metadata ---")
                    for k, v in metadata.items():
                        inspector_text.append(f"{k.strip('/')}: {v}")
                else:
                    inspector_text.append("--- Metadata ---")
                    inspector_text.append("None or unreadable.")
            except Exception as e:
                inspector_text.append("--- Metadata ---")
                inspector_text.append("Encrypted (cannot read without password).")

            # Security
            trailer = reader.trailer
            encrypt_dict = trailer.get("/Encrypt")
            if encrypt_dict:
                inspector_text.append("--- Security Properties ---")
                for k, v in encrypt_dict.items():
                    # Format byte strings for display if needed, ignore long byte streams
                    if k in ['/O', '/U', '/OE', '/UE', '/Perms']:
                        inspector_text.append(f"{k.strip('/')}: <binary data>")
                    else:
                        inspector_text.append(f"{k.strip('/')}: {v}")

            self.txt_inspector.insert(tk.END, "\n".join(inspector_text))

            # Run heuristics
            self.run_heuristics(inspector_text)

        except Exception as e:
            self.txt_inspector.insert(tk.END, f"Error reading PDF:\n{e}")

        self.txt_inspector.config(state="disabled")

    def run_heuristics(self, inspector_lines):
        full_text = "\n".join(inspector_lines).lower()

        # Heuristic 1: Common banking or financial PIN structures
        if "bank" in full_text or "statement" in full_text or "financial" in full_text:
            self.char_set_type.set("numeric")
            self.pwd_length.set(6)
            messagebox.showinfo("Auto-Config", "Detected financial document signature.\nSuggested pattern: 6-digit numeric PIN.")
            return

        # Heuristic 2: Certain producers commonly default to alphanumeric name-date hashes
        if "pdf_gen" in full_text or "producer: itext" in full_text or "creator: crystal" in full_text:
            self.char_set_type.set("alphanumeric")
            self.pwd_length.set(8)
            messagebox.showinfo("Auto-Config", "Detected common enterprise PDF generator.\nSuggested pattern: 8-character alphanumeric.")
            return

    def get_charset(self):
        ctype = self.char_set_type.get()
        if ctype == "numeric":
            return string.digits
        elif ctype == "alphanumeric":
            return string.ascii_letters + string.digits
        else:
            return string.ascii_letters + string.digits + string.punctuation

    def start_recovery(self):
        path = self.pdf_path.get()
        if not path:
            messagebox.showerror("Error", "Please select a PDF file.")
            return

        try:
            reader = PdfReader(path)
            if not reader.is_encrypted:
                messagebox.showinfo("Info", "This PDF file is not encrypted.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read PDF file:\n{e}")
            return

        charset = self.get_charset()
        length = self.pwd_length.get()
        prefix = self.pwd_prefix.get()

        self.total_passwords = len(charset) ** length

        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        self.stop_event = Event()
        self.result_queue = Queue()
        self.progress_queue = Queue()

        self.total_attempts = 0
        self.start_time = time.time()
        self.progress_var.set(0)
        self.lbl_status.config(text="Recovering...")

        self.manager_process = Process(target=recovery_manager, args=(
            path, charset, length, prefix, self.result_queue, self.progress_queue, self.stop_event, self.total_passwords
        ))
        self.manager_process.start()

        self.root.after(100, self.update_status)

    def stop_recovery(self):
        if self.is_running:
            self.stop_event.set()
            self.lbl_status.config(text="Stopping...")

    def update_status(self):
        if not self.is_running:
            return

        # Update progress
        while not self.progress_queue.empty():
            try:
                count = self.progress_queue.get_nowait()
                self.total_attempts += count
            except Exception:
                break

        # Calculate stats
        elapsed = time.time() - self.start_time
        speed = self.total_attempts / elapsed if elapsed > 0 else 0
        pct = (self.total_attempts / self.total_passwords) * 100 if self.total_passwords > 0 else 0

        self.progress_var.set(pct)
        self.lbl_stats.config(text=f"{self.total_attempts} attempts | {speed:.2f} attempts/sec | {pct:.2f}%")

        # Check for result
        if not self.result_queue.empty():
            try:
                pwd = self.result_queue.get_nowait()
                self.stop_event.set()
                self.is_running = False
                self.btn_start.config(state="normal")
                self.btn_stop.config(state="disabled")
                self.lbl_status.config(text="Success!")
                messagebox.showinfo("Success", f"Password recovered: {pwd}")
                return
            except Exception:
                pass

        # Check if finished without result
        if not self.manager_process.is_alive() and self.progress_queue.empty() and self.result_queue.empty():
            self.is_running = False
            self.btn_start.config(state="normal")
            self.btn_stop.config(state="disabled")
            if self.stop_event.is_set():
                self.lbl_status.config(text="Stopped by user.")
            else:
                self.lbl_status.config(text="Finished. Password not found.")
                messagebox.showinfo("Result", "Password not found in the given pattern.")
            return

        self.root.after(100, self.update_status)

if __name__ == '__main__':
    # Standard guard for multiprocessing on Windows
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = PDFRecoveryApp(root)
    root.mainloop()
