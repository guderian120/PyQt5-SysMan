import os
import sys
import csv
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, 
                            QTextEdit, QLabel, QLineEdit, QFileDialog, QGroupBox, 
                            QHBoxLayout, QCheckBox, QDialog, QDialogButtonBox, 
                            QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5 import QtGui
import subprocess
import random
from email_server import send_email, send_email_to_admin
import string



# This helper function generates a random temporary password
# with a mix of letters, digits, and special characters.
# The length of the password can be specified.
def generate_temp_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

def ensure_group_exists(group_name, sudo_password):
    # Check if group exists
    check_group = subprocess.run(['getent', 'group', group_name], stdout=subprocess.DEVNULL)
    if check_group.returncode != 0:
        print(f"Creating group '{group_name}'...")
        run_sudo_command(['groupadd', group_name], sudo_password)


def run_sudo_command(command_list, sudo_password):
    """Run a command with sudo and provide password via stdin."""
    process = subprocess.Popen(
        ['sudo', '-S'] + command_list,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    stdout, stderr = process.communicate(sudo_password + '\n')
    if process.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(command_list)}\nError: {stderr.strip()}")
    return stdout.strip()


"""            --------------------SUDO PASSWORD DIALOG SECTION----------------------------"""
# This class represents a dialog for entering the sudo password.
# It is shown at the start of the application to ensure
# that the user has the necessary privileges to perform
class SudoPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authentication Required")
        self.setWindowModality(Qt.ApplicationModal)
        self.setFixedSize(400, 150)
        
        layout = QVBoxLayout()
        
        label = QLabel("This application requires administrator privileges.\nPlease enter your sudo password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.verify_password)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(label)
        layout.addWidget(self.password_input)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
        
        # Style the dialog
        self.setStyleSheet("""
            QDialog {
                background-color: #f5f5f5;
            }
            QLabel {
                margin-bottom: 10px;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                margin-bottom: 15px;
            }
        """)
        
        self.sudo_password = None
    # This method verifies the entered password by attempting
    # to run a simple command with sudo privileges.
    # If the command succeeds, the password is accepted.
    # Otherwise, an error message is shown.
    def verify_password(self):
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Error", "Password cannot be empty!")
            return
            
        try:
            process = subprocess.Popen(
                ['sudo', '-S', 'echo', 'test'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate(password + '\n')
            
            if process.returncode == 0:
                self.sudo_password = password
                self.accept()
            else:
                QMessageBox.warning(self, "Authentication Failed", "Incorrect password or insufficient privileges!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to verify password: {str(e)}")









"""           --------------------WORKER THREAD SECTION----------------------------"""


# This class represents a worker thread that performs the
# user creation process in the background.
# It reads the CSV file, creates users, sets temporary passwords, 
class WorkerThread(QThread):
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool)

    def __init__(self, csv_path, send_email, admin_email, sudo_password):
        super().__init__()
        self.csv_path = csv_path
        self.send_email = send_email
        self.admin_email = admin_email
        self.sudo_password = sudo_password
        self.log_file = "iam_setup.log"

    def run(self):
        try:
            # Process CSV and create users
            with open(self.csv_path, 'r') as file:
                csv_reader = csv.DictReader(file)
                for row in csv_reader:
                    row = {key.strip(): value.strip() if isinstance(value, str) else value for key, value in row.items()}
                    username = row['username']
                    group = row.get('department', 'users')
                    full_name = row.get('full_name', '').split(" ")
                    email = row.get('email', '')
                    ensure_group_exists(group, self.sudo_password)
                    temp_password = generate_temp_password()
                    if not username:
                        self.log_and_emit(f"Error: Username is empty for row {row}")
                        continue
                    self.log_and_emit(f"Creating user: {username} from Department: {group}...")

                    # 1. Create the user

                    cmd = f"sudo -S useradd -m -G {group} -c '{"-".join(full_name)}' {username}"
                    cmd = cmd.split(' ')
                    process = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    stdout, stderr = process.communicate(self.sudo_password + '\n')

                    if process.returncode == 0:
                        self.log_and_emit(f"Successfully created user {username} with passwword {temp_password}")

                        # 2. Set a temporary password
                        passwd_cmd = f"echo '{username}:{temp_password}' | sudo -S chpasswd"
                        passwd_process = subprocess.Popen(
                            passwd_cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True,
                            universal_newlines=True
                        )
                        passwd_stdout, passwd_stderr = passwd_process.communicate(self.sudo_password + '\n')

                        if passwd_process.returncode != 0:
                            self.log_and_emit(f"Error setting password for {username}: {passwd_stderr.strip()}")
                            continue

                        # 3. Force password change on first login
                        chage_cmd = f"sudo -S chage -d 0 {username}"
                        chage_process = subprocess.Popen(
                            chage_cmd.split(),
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True
                        )
                        chage_stdout, chage_stderr = chage_process.communicate(self.sudo_password + '\n')

                        if chage_process.returncode != 0:
                            self.log_and_emit(f"Error forcing password change: {chage_stderr.strip()}")
                            continue

                        # 4. Send email with temporary password
                        if email:
                            self.log_and_emit(f"Sending credentials to {email}...")
                            send_email(email, full_name, username, temp_password)

                        self.log_and_emit(f"Successfully processed user {username}")
                    else:
                        self.log_and_emit(f"Error creating user {username}: {stderr.strip()}")
                        continue  # Skip to next user if there was an error

            # 5. Send log to admin if enabled
            if self.send_email and self.admin_email:
                self.log_and_emit(f"Sending log file to Admin: {self.admin_email}...")
                try:
                    send_email_to_admin(self.log_file, self.admin_email)
                except Exception as e:
                    self.log_and_emit(f"Failed to send email: {str(e)}")

            self.finished_signal.emit(True)

        except Exception as e:
            self.log_and_emit(f"Error: {str(e)}")
            self.finished_signal.emit(False)
    def log_and_emit(self, message):
        # Emit to UI
        self.update_signal.emit(message)

        # Append to log file
        with open("iam_setup.log", "a") as log_file:
            log_file.write(message + "\n")
            log_file.flush()
            os.fsync(log_file.fileno())  








"""
            --------------------MAIN GUI SECTION----------------------------
"""

# This class represents the main GUI of the application.
# It contains all the UI elements and handles user interactions.
# The GUI is built using PyQt5 and is designed to be modern and user-friendly.
class SystemManagementGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sudo_password = None
        
        # First show the sudo password dialog
        self.show_sudo_dialog()
        
        if not self.sudo_password:
            sys.exit(1)  # Exit if no password provided
            
        # Only proceed with main window if we have sudo access
        self.init_ui()
        
    def show_sudo_dialog(self):
        dialog = SudoPasswordDialog()
        if dialog.exec_() == QDialog.Accepted:
            self.sudo_password = dialog.sudo_password
        else:
            QMessageBox.warning(None, "Access Denied", "This application cannot run without sudo privileges.")
            
    def init_ui(self):
        self.setWindowTitle("System Management Tool")
        self.setGeometry(100, 100, 800, 600)
        
        # Set window icon
        self.setWindowIcon(QtGui.QIcon("system-config-users.png"))  # Replace with your icon
        
        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout
        self.main_layout = QVBoxLayout()
        self.central_widget.setLayout(self.main_layout)
        
        # Apply stylesheet for modern look
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                border: 1px solid #ccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
            }
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 8px 16px;
                text-align: center;
                text-decoration: none;
                font-size: 14px;
                margin: 4px 2px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 5px;
                font-family: monospace;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
        """)
        
        # Create UI elements
        self.create_file_selection_group()
        self.create_email_group()
        self.create_console_output()
        self.create_action_buttons()
        
    def create_file_selection_group(self):
        group = QGroupBox("1. Select CSV File")
        layout = QHBoxLayout()
        
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("No file selected")
        self.file_path.setReadOnly(True)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_file)
        
        layout.addWidget(self.file_path, stretch=4)
        layout.addWidget(browse_btn, stretch=1)
        
        group.setLayout(layout)
        self.main_layout.addWidget(group)
        
    def create_email_group(self):
        group = QGroupBox("2. Email Notification (Optional)")
        layout = QVBoxLayout()
        
        self.email_checkbox = QCheckBox("Send email notification when done")
        self.email_checkbox.setChecked(False)
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("admin@example.com")
        self.email_input.setEnabled(False)
        
        self.email_checkbox.stateChanged.connect(lambda: self.email_input.setEnabled(self.email_checkbox.isChecked()))
        
        layout.addWidget(self.email_checkbox)
        layout.addWidget(self.email_input)
        
        group.setLayout(layout)
        self.main_layout.addWidget(group)
        
    def create_console_output(self):
        group = QGroupBox("3. Console Output")
        layout = QVBoxLayout()
        
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QtGui.QFont("Courier", 10))
        
        layout.addWidget(self.console_output)
        group.setLayout(layout)
        self.main_layout.addWidget(group)
        
    def create_action_buttons(self):
        layout = QHBoxLayout()
        
        self.execute_btn = QPushButton("Execute")
        self.execute_btn.clicked.connect(self.execute_commands)
        self.execute_btn.setEnabled(False)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_console)
        
        layout.addWidget(self.execute_btn)
        layout.addWidget(self.clear_btn)
        
        self.main_layout.addLayout(layout)
        
    def browse_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select CSV File", "", "CSV Files (*.csv)")

        
        if file_path:
            self.file_path.setText(file_path)
            self.execute_btn.setEnabled(True)
            self.log_message(f"Selected file: {file_path}")
            
    def execute_commands(self):
        csv_path = self.file_path.text()
        send_email = self.email_checkbox.isChecked()
        admin_email = self.email_input.text() if send_email else None
        
        if not csv_path:
            self.log_message("Error: No CSV file selected")
            return
            
        self.log_message("\nStarting user creation process...")
        self.execute_btn.setEnabled(False)
        
        # Create and start worker thread
        self.worker = WorkerThread(csv_path, send_email, admin_email, self.sudo_password)
        self.worker.update_signal.connect(self.log_message)
        self.worker.finished_signal.connect(self.on_process_finished)
        self.worker.start()
        
    def on_process_finished(self, success):
        self.execute_btn.setEnabled(True)
        if success:
            self.log_message("\nProcess completed successfully!")
        else:
            self.log_message("\nProcess completed with errors!")
        
    def log_message(self, message):
        self.console_output.append(message)
        # Auto-scroll to bottom
        self.console_output.verticalScrollBar().setValue(
            self.console_output.verticalScrollBar().maximum()
        )
        
    def clear_console(self):
        self.console_output.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style for modern look
    app.setStyle('Fusion')
    
    window = SystemManagementGUI()
    window.show()
    sys.exit(app.exec_())