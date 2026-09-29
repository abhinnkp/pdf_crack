import time
import multiprocessing
from multiprocessing import Queue, Event
import string
import os
from pypdf import PdfWriter
from pdf_recovery import recovery_manager

def run_bench(pdf_file, target_pwd, workers):
    result_queue = Queue()
    progress_queue = Queue()
    stop_event = Event()
    char_set = string.digits
    manager_process = multiprocessing.Process(target=recovery_manager, args=(
        pdf_file, char_set, 6, "", result_queue, progress_queue, stop_event, 100000, workers
    ))

    start = time.time()
    manager_process.start()
    attempts = 0
    while True:
        while not progress_queue.empty():
            try:
                attempts += progress_queue.get_nowait()
            except Exception:
                pass
        if not result_queue.empty():
            result_queue.get()
            stop_event.set()
            break
        if not manager_process.is_alive():
            break
        time.sleep(0.01)
    end = time.time()
    manager_process.join()
    return attempts, end - start

def execute_benchmarks():
    target_pwd = "002000"
    pdf_r6 = "test_r6_bench.pdf"
    print("Generating Benchmark PDFs...")
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.encrypt(target_pwd, algorithm="AES-256")
    with open(pdf_r6, "wb") as f:
        writer.write(f)

    pdf_r6_baseline = "test_r6_baseline.pdf"
    with open(pdf_r6, "rb") as f:
        pdf_data = f.read()
    pdf_data_hacked = pdf_data.replace(b"/AESV3", b"/AESV2")
    with open(pdf_r6_baseline, "wb") as f:
        f.write(pdf_data_hacked)

    workers_to_test = [1, 2, 4]
    print(f"Available System CPUs: {multiprocessing.cpu_count()}")
    print("-" * 50)

    for w in workers_to_test:
        if w > multiprocessing.cpu_count():
            continue
        print(f"Running Benchmark with {w} Worker(s)")

        attempts_base, elapsed_base = run_bench(pdf_r6_baseline, target_pwd, w)
        tput_base = attempts_base / elapsed_base if elapsed_base > 0 else 0

        attempts_opt, elapsed_opt = run_bench(pdf_r6, target_pwd, w)
        tput_opt = attempts_opt / elapsed_opt if elapsed_opt > 0 else 0

        print(f"  Baseline (reader.decrypt): {tput_base:.2f} attempts/sec")
        print(f"  Optimized (R6 Direct)    : {tput_opt:.2f} attempts/sec")
        if tput_base > 0:
            print(f"  Speedup                  : {tput_opt / tput_base:.2f}x")
        print("-" * 50)

    if os.path.exists(pdf_r6): os.remove(pdf_r6)
    if os.path.exists(pdf_r6_baseline): os.remove(pdf_r6_baseline)

if __name__ == '__main__':
    execute_benchmarks()
