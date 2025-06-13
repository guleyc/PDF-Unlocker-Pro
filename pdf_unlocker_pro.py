import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PyPDF2 import PdfReader, PdfWriter
import threading
import os
import time
import base64
from datetime import datetime

class PDFUnlockerPro:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Unlocker Pro")
        self.root.geometry("600x500")
        self.root.configure(bg='#f0f0f0')
        
        # Icon setup (optional)
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass
        
        self.setup_ui()
        self.is_processing = False
        
        # Protected author information
        self._author_info = self._get_protected_info()
    
    def _get_protected_info(self):
        """Protected author information - difficult to modify"""
        # Base64 encoded author information
        author_data = "Q2FnYXRheSBHdWxleQ=="  # "Cagatay Guley"
        website_data = "Z3VsZXkuY29tLnRy"      # "guley.com.tr"
        
        try:
            author = base64.b64decode(author_data).decode('utf-8')
            website = base64.b64decode(website_data).decode('utf-8')
            return {"author": author, "website": website}
        except:
            return {"author": "Cagatay Guley", "website": "guley.com.tr"}
    
    def setup_ui(self):
        """Setup user interface"""
        # Main title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        title_frame.pack(fill='x')
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame, 
            text="🔓 PDF Unlocker Pro", 
            font=('Arial', 18, 'bold'),
            fg='white', 
            bg='#2c3e50'
        )
        title_label.pack(expand=True)
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # File selection section
        file_frame = tk.LabelFrame(main_frame, text="📁 File Selection", font=('Arial', 10, 'bold'), bg='#f0f0f0')
        file_frame.pack(fill='x', pady=(0, 15))
        
        # Input file
        tk.Label(file_frame, text="Locked PDF:", bg='#f0f0f0', font=('Arial', 9)).grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.input_path = tk.StringVar()
        input_entry = tk.Entry(file_frame, textvariable=self.input_path, width=50, font=('Arial', 9))
        input_entry.grid(row=0, column=1, padx=5, pady=5)
        
        input_btn = tk.Button(
            file_frame, 
            text="📂 Browse", 
            command=self.select_input_file,
            bg='#3498db', 
            fg='white', 
            font=('Arial', 9, 'bold'),
            relief=tk.FLAT,
            padx=10
        )
        input_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Output file
        tk.Label(file_frame, text="Output location:", bg='#f0f0f0', font=('Arial', 9)).grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.output_path = tk.StringVar()
        output_entry = tk.Entry(file_frame, textvariable=self.output_path, width=50, font=('Arial', 9))
        output_entry.grid(row=1, column=1, padx=5, pady=5)
        
        output_btn = tk.Button(
            file_frame, 
            text="📂 Browse", 
            command=self.select_output_file,
            bg='#3498db', 
            fg='white', 
            font=('Arial', 9, 'bold'),
            relief=tk.FLAT,
            padx=10
        )
        output_btn.grid(row=1, column=2, padx=5, pady=5)
        
        # Process button
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(pady=15)
        
        self.process_btn = tk.Button(
            button_frame,
            text="🔓 UNLOCK PDF",
            command=self.start_unlock_process,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 12, 'bold'),
            relief=tk.FLAT,
            padx=30,
            pady=10,
            cursor='hand2'
        )
        self.process_btn.pack()
        
        # Progress bar
        progress_frame = tk.Frame(main_frame, bg='#f0f0f0')
        progress_frame.pack(fill='x', pady=(10, 0))
        
        self.progress = ttk.Progressbar(
            progress_frame, 
            mode='indeterminate',
            style='custom.Horizontal.TProgressbar'
        )
        self.progress.pack(fill='x')
        
        self.status_label = tk.Label(
            progress_frame, 
            text="Ready", 
            bg='#f0f0f0', 
            font=('Arial', 9),
            fg='#2c3e50'
        )
        self.status_label.pack(pady=(5, 0))
        
        # Log section
        log_frame = tk.LabelFrame(main_frame, text="📋 Process Log", font=('Arial', 10, 'bold'), bg='#f0f0f0')
        log_frame.pack(fill='both', expand=True, pady=(15, 0))
        
        # Log text widget
        log_inner_frame = tk.Frame(log_frame)
        log_inner_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(
            log_inner_frame, 
            height=12, 
            font=('Consolas', 9),
            bg='#2c3e50',
            fg='#ecf0f1',
            insertbackground='white',
            relief=tk.FLAT
        )
        self.log_text.pack(side='left', fill='both', expand=True)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(log_inner_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        # Bottom info - Protected author information
        info_frame = tk.Frame(self.root, bg='#34495e', height=30)
        info_frame.pack(fill='x', side='bottom')
        info_frame.pack_propagate(False)
        
        author_info = self._author_info
        info_text = f"© 2025 {author_info['author']} - {author_info['website']} | PDF Unlocker Pro"
        
        info_label = tk.Label(
            info_frame,
            text=info_text,
            bg='#34495e',
            fg='#bdc3c7',
            font=('Arial', 8)
        )
        info_label.pack(expand=True)
        
        # Initial log messages
        self.log("PDF Unlocker Pro started successfully")
        self.log("Select your locked PDF file and unlock it!")
    
    def log(self, message):
        """Add log message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        self.log_text.insert(tk.END, formatted_message + "\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def select_input_file(self):
        """Select input file"""
        filename = filedialog.askopenfilename(
            title="Select Locked PDF File",
            filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")]
        )
        if filename:
            self.input_path.set(filename)
            self.log(f"Input file selected: {os.path.basename(filename)}")
            
            # Auto-generate output filename
            base_name = os.path.splitext(filename)[0]
            output_name = f"{base_name}_unlocked.pdf"
            self.output_path.set(output_name)
            self.log(f"Output file auto-set: {os.path.basename(output_name)}")
    
    def select_output_file(self):
        """Select output file"""
        filename = filedialog.asksaveasfilename(
            title="Save Unlocked PDF",
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")]
        )
        if filename:
            self.output_path.set(filename)
            self.log(f"Output file selected: {os.path.basename(filename)}")
    
    def update_status(self, message):
        """Update status message"""
        self.status_label.config(text=message)
        self.root.update()
    
    def start_unlock_process(self):
        """Start unlock process"""
        if self.is_processing:
            return
        
        input_file = self.input_path.get().strip()
        output_file = self.output_path.get().strip()
        
        if not input_file:
            messagebox.showerror("Error", "Please select an input file!")
            return
        
        if not output_file:
            messagebox.showerror("Error", "Please specify an output file!")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", "Input file not found!")
            return
        
        # Set UI to processing mode
        self.is_processing = True
        self.process_btn.config(state='disabled', text='Processing...')
        self.progress.start(10)
        self.update_status("Analyzing PDF...")
        
        # Start background thread
        thread = threading.Thread(target=self.unlock_pdf_thread, args=(input_file, output_file))
        thread.daemon = True
        thread.start()
    
    def unlock_pdf_thread(self, input_file, output_file):
        """PDF unlock process (background)"""
        try:
            self.log("="*50)
            self.log("PDF unlock process started")
            self.log(f"Input: {os.path.basename(input_file)}")
            self.log(f"Output: {os.path.basename(output_file)}")
            
            # Read PDF
            self.update_status("Reading PDF file...")
            reader = PdfReader(input_file)
            self.log(f"PDF read successfully - {len(reader.pages)} pages")
            
            success = False
            used_password = None
            
            if not reader.is_encrypted:
                self.log("✅ PDF is already open! No restrictions.")
                success = True
            else:
                self.log("🔒 PDF is encrypted, unlocking...")
                self.update_status("Trying passwords...")
                
                # 1. Try owner password (empty string)
                if reader.decrypt(""):
                    self.log("✅ Owner password restrictions removed!")
                    success = True
                else:
                    # 2. Try common passwords
                    self.log("🔍 Trying common passwords...")
                    common_passwords = [
                        "123", "123456", "1234", "12345", "password", 
                        "admin", "user", "pdf", "document", "test",
                        "demo", "secret", "private", "2023", "2024", "2025",
                        "a", "1", "12", "abc", "qwerty", "asdf"
                    ]
                    
                    for i, pwd in enumerate(common_passwords):
                        self.update_status(f"Trying password: {pwd}")
                        try:
                            if reader.decrypt(pwd):
                                self.log(f"✅ Password found: '{pwd}'")
                                success = True
                                used_password = pwd
                                break
                        except:
                            continue
                    
                    if not success:
                        # 3. Short brute force (1-3 characters)
                        self.log("🔄 Trying short brute force...")
                        import itertools
                        import string
                        
                        chars = string.ascii_lowercase + string.digits
                        
                        for length in range(1, 4):  # 1-3 characters
                            self.update_status(f"Brute force: {length} characters")
                            self.log(f"  Trying {length} character combinations...")
                            
                            count = 0
                            for combo in itertools.product(chars, repeat=length):
                                password = ''.join(combo)
                                try:
                                    if reader.decrypt(password):
                                        self.log(f"✅ Password found: '{password}'")
                                        success = True
                                        used_password = password
                                        break
                                except:
                                    continue
                                
                                count += 1
                                if count % 100 == 0:
                                    self.update_status(f"Brute force: {password} ({count} attempts)")
                            
                            if success:
                                break
            
            if success:
                # Create unlocked PDF
                self.update_status("Creating unlocked PDF...")
                self.log("📝 Creating unlocked PDF...")
                
                writer = PdfWriter()
                for i, page in enumerate(reader.pages):
                    writer.add_page(page)
                    if i % 10 == 0:
                        self.update_status(f"Processing page: {i+1}/{len(reader.pages)}")
                
                # Save file
                with open(output_file, 'wb') as f:
                    writer.write(f)
                
                self.log(f"✅ Success! Unlocked PDF saved: {os.path.basename(output_file)}")
                self.update_status("Completed!")
                
                # Success message
                result_msg = f"PDF unlocked successfully!\n\nFile: {os.path.basename(output_file)}"
                if used_password:
                    result_msg += f"\nPassword used: '{used_password}'"
                
                messagebox.showinfo("Success! 🎉", result_msg)
                
            else:
                self.log("❌ Password not found!")
                self.log("This PDF is protected with a stronger password.")
                self.update_status("Password not found")
                messagebox.showwarning(
                    "Password Not Found", 
                    "Could not find the PDF password.\n\nThis file is protected with a strong password.\nIf you remember the password, you can enter it manually."
                )
        
        except Exception as e:
            self.log(f"❌ Error occurred: {str(e)}")
            self.update_status("Error!")
            messagebox.showerror("Error", f"An error occurred during processing:\n\n{str(e)}")
        
        finally:
            # Return UI to normal
            self.is_processing = False
            self.progress.stop()
            self.process_btn.config(state='normal', text='🔓 UNLOCK PDF')
            if not success:
                self.update_status("Ready")

def main():
    root = tk.Tk()
    app = PDFUnlockerPro(root)
    
    # Ask for confirmation when closing window
    def on_closing():
        if app.is_processing:
            if messagebox.askokcancel("Exit", "Process is running. Are you sure you want to exit?"):
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()