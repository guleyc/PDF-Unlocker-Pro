import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PyPDF2 import PdfReader, PdfWriter
import threading
import os
import time
import hashlib
from datetime import datetime

class PDFUnlockerPro:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Unlocker Pro")
        self.root.geometry("600x500")
        self.root.configure(bg='#f0f0f0')
        
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass
        
        # Obfuscated author info
        self._auth_data = self._init_auth()
        
        self.setup_ui()
        self.is_processing = False
    
    def _init_auth(self):
        """Initialize author information with multiple layers of obfuscation"""
        # XOR encoded data
        encoded_name = [67, 97, 103, 97, 116, 97, 121, 32, 71, 117, 108, 101, 121]
        encoded_site = [103, 117, 108, 101, 121, 46, 99, 111, 109, 46, 116, 114]
        
        # Additional layer with checksum
        name_hash = 0x4A5F2E3D  # Static hash for validation
        site_hash = 0x8B7C1A9F  # Static hash for validation
        
        try:
            # Decode name
            decoded_name = ''.join(chr(c) for c in encoded_name)
            # Decode site  
            decoded_site = ''.join(chr(c) for c in encoded_site)
            
            # Validate with simple checksum
            if sum(encoded_name) & 0xFFFFFFFF == name_hash:
                if sum(encoded_site) & 0xFFFFFFFF == site_hash:
                    return {"n": decoded_name, "s": decoded_site, "v": True}
            
            # Fallback if validation fails
            return {"n": "PDF Unlocker Pro", "s": "github.com", "v": False}
            
        except:
            return {"n": "PDF Unlocker Pro", "s": "github.com", "v": False}
    
    def _get_footer_text(self):
        """Generate footer text with integrity check"""
        auth = getattr(self, '_auth_data', {"n": "Unknown", "s": "unknown.com", "v": False})
        
        if auth.get('v', False):
            # Use real author info
            year = datetime.now().year
            footer_parts = ["©", str(year), auth['n'], "-", auth['s'], "|", "PDF", "Unlocker", "Pro"]
            return " ".join(footer_parts)
        else:
            # Generic footer
            return "© 2025 PDF Unlocker Pro | Open Source Tool"
    
    def setup_ui(self):
        """Setup user interface"""
        # Title
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
        
        # Main content
        main_frame = tk.Frame(self.root, bg='#f0f0f0', padx=20, pady=20)
        main_frame.pack(fill='both', expand=True)
        
        # File selection
        self._setup_file_selection(main_frame)
        
        # Process button
        self._setup_process_button(main_frame)
        
        # Progress section
        self._setup_progress_section(main_frame)
        
        # Log section
        self._setup_log_section(main_frame)
        
        # Footer
        self._setup_protected_footer()
        
        # Initial messages
        self.log("PDF Unlocker Pro initialized successfully")
        self.log("Ready to unlock PDF files!")
    
    def _setup_file_selection(self, parent):
        """Setup file selection UI"""
        file_frame = tk.LabelFrame(parent, text="📁 File Selection", font=('Arial', 10, 'bold'), bg='#f0f0f0')
        file_frame.pack(fill='x', pady=(0, 15))
        
        # Input file
        tk.Label(file_frame, text="Locked PDF:", bg='#f0f0f0', font=('Arial', 9)).grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.input_path = tk.StringVar()
        tk.Entry(file_frame, textvariable=self.input_path, width=50, font=('Arial', 9)).grid(row=0, column=1, padx=5, pady=5)
        
        tk.Button(
            file_frame, text="📂 Browse", command=self.select_input_file,
            bg='#3498db', fg='white', font=('Arial', 9, 'bold'),
            relief=tk.FLAT, padx=10
        ).grid(row=0, column=2, padx=5, pady=5)
        
        # Output file
        tk.Label(file_frame, text="Output location:", bg='#f0f0f0', font=('Arial', 9)).grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.output_path = tk.StringVar()
        tk.Entry(file_frame, textvariable=self.output_path, width=50, font=('Arial', 9)).grid(row=1, column=1, padx=5, pady=5)
        
        tk.Button(
            file_frame, text="📂 Browse", command=self.select_output_file,
            bg='#3498db', fg='white', font=('Arial', 9, 'bold'),
            relief=tk.FLAT, padx=10
        ).grid(row=1, column=2, padx=5, pady=5)
    
    def _setup_process_button(self, parent):
        """Setup process button"""
        button_frame = tk.Frame(parent, bg='#f0f0f0')
        button_frame.pack(pady=15)
        
        self.process_btn = tk.Button(
            button_frame, text="🔓 UNLOCK PDF", command=self.start_unlock_process,
            bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'),
            relief=tk.FLAT, padx=30, pady=10, cursor='hand2'
        )
        self.process_btn.pack()
    
    def _setup_progress_section(self, parent):
        """Setup progress section"""
        progress_frame = tk.Frame(parent, bg='#f0f0f0')
        progress_frame.pack(fill='x', pady=(10, 0))
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.pack(fill='x')
        
        self.status_label = tk.Label(
            progress_frame, text="Ready", bg='#f0f0f0', 
            font=('Arial', 9), fg='#2c3e50'
        )
        self.status_label.pack(pady=(5, 0))
    
    def _setup_log_section(self, parent):
        """Setup log section"""
        log_frame = tk.LabelFrame(parent, text="📋 Process Log", font=('Arial', 10, 'bold'), bg='#f0f0f0')
        log_frame.pack(fill='both', expand=True, pady=(15, 0))
        
        log_inner_frame = tk.Frame(log_frame)
        log_inner_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(
            log_inner_frame, height=12, font=('Consolas', 9),
            bg='#2c3e50', fg='#ecf0f1', insertbackground='white', relief=tk.FLAT
        )
        self.log_text.pack(side='left', fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(log_inner_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.pack(side='right', fill='y')
        self.log_text.configure(yscrollcommand=scrollbar.set)
    
    def _setup_protected_footer(self):
        """Setup protected footer"""
        try:
            info_frame = tk.Frame(self.root, bg='#34495e', height=30)
            info_frame.pack(fill='x', side='bottom')
            info_frame.pack_propagate(False)
            
            footer_text = self._get_footer_text()
            
            info_label = tk.Label(
                info_frame, text=footer_text, bg='#34495e', 
                fg='#bdc3c7', font=('Arial', 8)
            )
            info_label.pack(expand=True)
            
            # Hide the label creation from easy modification
            info_label.bind("<Button-1>", lambda e: self._easter_egg())
            
        except Exception:
            # Emergency fallback
            self._create_fallback_footer()
    
    def _create_fallback_footer(self):
        """Fallback footer creation"""
        info_frame = tk.Frame(self.root, bg='#34495e', height=30)
        info_frame.pack(fill='x', side='bottom')
        info_frame.pack_propagate(False)
        
        tk.Label(
            info_frame, text="© 2025 PDF Unlocker Pro | Open Source",
            bg='#34495e', fg='#bdc3c7', font=('Arial', 8)
        ).pack(expand=True)
    
    def _easter_egg(self):
        """Hidden easter egg for credits"""
        auth = getattr(self, '_auth_data', {"n": "Unknown", "s": "unknown.com", "v": False})
        if auth.get('v', False):
            messagebox.showinfo(
                "About Developer", 
                f"PDF Unlocker Pro\n\nDeveloped by: {auth['n']}\nWebsite: {auth['s']}\n\nThank you for using our software!"
            )
    
    def log(self, message):
        """Add log message"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] {message}"
            self.log_text.insert(tk.END, formatted_message + "\n")
            self.log_text.see(tk.END)
            self.root.update()
        except:
            print(f"[LOG] {message}")
    
    def select_input_file(self):
        """Select input file"""
        try:
            filename = filedialog.askopenfilename(
                title="Select Locked PDF File",
                filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")]
            )
            if filename:
                self.input_path.set(filename)
                self.log(f"Input file selected: {os.path.basename(filename)}")
                
                base_name = os.path.splitext(filename)[0]
                output_name = f"{base_name}_unlocked.pdf"
                self.output_path.set(output_name)
                self.log(f"Output file auto-set: {os.path.basename(output_name)}")
        except Exception as e:
            self.log(f"Error selecting input file: {str(e)}")
            messagebox.showerror("Error", f"Failed to select input file: {str(e)}")
    
    def select_output_file(self):
        """Select output file"""
        try:
            filename = filedialog.asksaveasfilename(
                title="Save Unlocked PDF", defaultextension=".pdf",
                filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")]
            )
            if filename:
                self.output_path.set(filename)
                self.log(f"Output file selected: {os.path.basename(filename)}")
        except Exception as e:
            self.log(f"Error selecting output file: {str(e)}")
            messagebox.showerror("Error", f"Failed to select output file: {str(e)}")
    
    def update_status(self, message):
        """Update status message"""
        try:
            self.status_label.config(text=message)
            self.root.update()
        except:
            pass
    
    def start_unlock_process(self):
        """Start unlock process"""
        if getattr(self, 'is_processing', False):
            return
        
        try:
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
            
            self.is_processing = True
            self.process_btn.config(state='disabled', text='Processing...')
            self.progress.start(10)
            self.update_status("Analyzing PDF...")
            
            thread = threading.Thread(target=self.unlock_pdf_thread, args=(input_file, output_file))
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            self.log(f"Error starting unlock process: {str(e)}")
            messagebox.showerror("Error", f"Failed to start unlock process: {str(e)}")
            self.is_processing = False
    
    def unlock_pdf_thread(self, input_file, output_file):
        """PDF unlock process (background)"""
        success = False
        try:
            self.log("="*50)
            self.log("PDF unlock process started")
            self.log(f"Input: {os.path.basename(input_file)}")
            self.log(f"Output: {os.path.basename(output_file)}")
            
            self.update_status("Reading PDF file...")
            reader = PdfReader(input_file)
            self.log(f"PDF read successfully - {len(reader.pages)} pages")
            
            used_password = None
            
            if not reader.is_encrypted:
                self.log("✅ PDF is already open! No restrictions.")
                success = True
            else:
                self.log("🔒 PDF is encrypted, unlocking...")
                self.update_status("Trying passwords...")
                
                # Owner password bypass
                if reader.decrypt(""):
                    self.log("✅ Owner password restrictions removed!")
                    success = True
                else:
                    # Common passwords
                    self.log("🔍 Trying common passwords...")
                    common_passwords = [
                        "123", "123456", "1234", "12345", "password", 
                        "admin", "user", "pdf", "document", "test",
                        "demo", "secret", "private", "2023", "2024", "2025",
                        "a", "1", "12", "abc", "qwerty", "asdf"
                    ]
                    
                    for pwd in common_passwords:
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
                        # Short brute force
                        self.log("🔄 Trying short brute force...")
                        try:
                            import itertools
                            import string
                            
                            chars = string.ascii_lowercase + string.digits
                            
                            for length in range(1, 4):
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
                        except Exception as e:
                            self.log(f"Brute force error: {str(e)}")
            
            if success:
                self.update_status("Creating unlocked PDF...")
                self.log("📝 Creating unlocked PDF...")
                
                writer = PdfWriter()
                for i, page in enumerate(reader.pages):
                    writer.add_page(page)
                    if i % 10 == 0:
                        self.update_status(f"Processing page: {i+1}/{len(reader.pages)}")
                
                with open(output_file, 'wb') as f:
                    writer.write(f)
                
                self.log(f"✅ Success! Unlocked PDF saved: {os.path.basename(output_file)}")
                self.update_status("Completed!")
                
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
                    "Could not find the PDF password.\n\nThis file is protected with a strong password."
                )
        
        except Exception as e:
            self.log(f"❌ Error occurred: {str(e)}")
            self.update_status("Error!")
            messagebox.showerror("Error", f"An error occurred during processing:\n\n{str(e)}")
        
        finally:
            try:
                self.is_processing = False
                self.progress.stop()
                self.process_btn.config(state='normal', text='🔓 UNLOCK PDF')
                if not success:
                    self.update_status("Ready")
            except:
                pass

def main():
    """Main function with error handling"""
    try:
        root = tk.Tk()
        app = PDFUnlockerPro(root)
        
        def on_closing():
            try:
                if getattr(app, 'is_processing', False):
                    if messagebox.askokcancel("Exit", "Process is running. Are you sure you want to exit?"):
                        root.destroy()
                else:
                    root.destroy()
            except:
                root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
        
    except Exception as e:
        try:
            import tkinter.messagebox as msgbox
            msgbox.showerror("Critical Error", f"Failed to start PDF Unlocker Pro:\n\n{str(e)}")
        except:
            print(f"Critical Error: {str(e)}")

if __name__ == "__main__":
    main()