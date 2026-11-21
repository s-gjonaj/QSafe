import sys
import os
from PyQt6.QtCore import Qt
from crypto import derive_key
from database import init_db, vault_exists, save_meta, get_salt, load_entries, save_entries

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QDialog,
    QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit,
    QListWidget, QMessageBox,
)


# class for login window , long-winded
class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QSafe")
        self.setFixedSize(380, 500)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(16)


        self.logo_label = QLabel() #TODO: sortout why svgs arent working
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo_label.setText("QSafe")
        self.logo_label.setStyleSheet("font-size: 96px; font-weight: bold;")
        layout.addWidget(self.logo_label)

        layout.addStretch()

        # pass fields
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("master pass")
        self.password_input.returnPressed.connect(self.attempt_login)
        layout.addWidget(self.password_input)

        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_input.setPlaceholderText("confirm pass")
        self.confirm_input.returnPressed.connect(self.attempt_login)
        layout.addWidget(self.confirm_input)

        layout.addStretch()

        # vault buttons
        self.create_btn = QPushButton("create vault")
        self.create_btn.clicked.connect(self.attempt_login)
        layout.addWidget(self.create_btn)

        self.reset_btn = QPushButton("reset vault")
        self.reset_btn.clicked.connect(self.reset_vault)
        layout.addWidget(self.reset_btn)

        self.status = QLabel("")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status)

        init_db()
        if vault_exists():
            self.confirm_input.hide()
            self.create_btn.setText("unlock")
        else:
            self.reset_btn.hide()

    def attempt_login(self):
        password = self.password_input.text()

        if not password:
            self.status.setText("Please enter a password.")
            return

        if not vault_exists():
            confirm = self.confirm_input.text()
            if password != confirm:
                self.status.setText("Passwords don't match.")
                return
            if len(password) < 8:
                self.status.setText("Password must be at least 8 characters.") # can be modified to change
                return

            salt = os.urandom(32)
            key = derive_key(password, salt)
            save_meta(salt, key)
            save_entries(key, [])
            self.open_vault(key)

        else:
            salt = get_salt()
            key = derive_key(password, salt)
            try:
                load_entries(key)
                self.open_vault(key)
            except Exception:
                self.status.setText("Wrong password.")

    def reset_vault(self):
        from database import VAULT_PATH
        reply = QMessageBox.question(
            self, "Reset Vault",
            "this will PERMANENTLY delete your vault and all saved passwords. are you sure?",
        )
        if reply == QMessageBox.StandardButton.Yes:
            if VAULT_PATH.exists():
                VAULT_PATH.unlink()
            self.new_login = LoginWindow()
            self.new_login.show()
            self.close()

    def open_vault(self, key: bytes):
        self.vault_window = VaultWindow(key)
        self.vault_window.show()
        self.close()

# class for the main window (the actual vault)
class VaultWindow(QMainWindow):
    def __init__(self, key: bytes):
        super().__init__()
        self.key = key
        self.entries = load_entries(key)

        self.setWindowTitle("QSafe Vault")
        self.setMinimumSize(400, 500)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        # top bar
        top = QHBoxLayout()
        top.addWidget(QLabel("Your passwords"))
        add_btn = QPushButton("+ Add")
        add_btn.clicked.connect(self.add_entry)
        top.addStretch()
        top.addWidget(add_btn)
        layout.addLayout(top)

        # entry list showing titles of entries
        self.list_widget = QListWidget()
        self.list_widget.currentRowChanged.connect(self.on_select)
        layout.addWidget(self.list_widget)

        # edit button
        bottom = QHBoxLayout()
        self.edit_btn = QPushButton("Edit")
        self.edit_btn.setEnabled(False)
        self.edit_btn.clicked.connect(self.open_entry)
        bottom.addStretch()
        bottom.addWidget(self.edit_btn)
        layout.addLayout(bottom)

        self.refresh_list()

    def on_select(self, row: int):
        self.edit_btn.setEnabled(row >= 0)

    def refresh_list(self):
        self.entries = load_entries(self.key)
        self.list_widget.clear()
        for entry in self.entries:
            self.list_widget.addItem(entry["title"])

    def open_entry(self):
        row = self.list_widget.currentRow()
        if row < 0:
            return
        entry = self.entries[row]
        self.entry_window = EntryWindow(entry, row, self)
        self.entry_window.show()

    def add_entry(self):
        dialog = AddEntryDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.entries.append(dialog.result)
            save_entries(self.key, self.entries)
            self.refresh_list()

# class for the entries window
class EntryWindow(QMainWindow):
    def __init__(self, entry: dict, row: int, vault_window: VaultWindow):
        super().__init__()
        self.entry = entry
        self.row = row
        self.vault_window = vault_window

        self.setWindowTitle(entry["title"])
        self.setFixedSize(400, 420)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setSpacing(10)

        self.title_input = QLineEdit(entry.get("title", ""))
        self.username_input = QLineEdit(entry.get("username", ""))
        self.password_input = QLineEdit(entry.get("password", ""))
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.description_input = QTextEdit()
        self.description_input.setPlainText(entry.get("description", ""))
        self.description_input.setFixedHeight(100)
        self.description_input.setPlaceholderText("Optional description…")

        form.addRow("Title", self.title_input)
        form.addRow("Username", self.username_input)
        form.addRow("Password", self.password_input)
        form.addRow("Description", self.description_input)
        layout.addLayout(form)

        show_btn = QPushButton("Show Password")
        show_btn.clicked.connect(self.toggle_password)
        layout.addWidget(show_btn)

        layout.addStretch()

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("Copy Password")
        save_btn = QPushButton("Save")
        delete_btn = QPushButton("Delete")
        copy_btn.clicked.connect(self.copy_password)
        save_btn.clicked.connect(self.save_entry)
        delete_btn.clicked.connect(self.delete_entry)
        btn_row.addWidget(copy_btn)
        btn_row.addStretch()
        btn_row.addWidget(save_btn)
        btn_row.addWidget(delete_btn)
        layout.addLayout(btn_row)

    def toggle_password(self):
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

    def copy_password(self):
        QApplication.clipboard().setText(self.password_input.text())

    def save_entry(self):
        title = self.title_input.text().strip()
        if not title:
            QMessageBox.warning(self, "Error", "title is required.")
            return
        self.vault_window.entries[self.row] = {
            "title": title,
            "username": self.username_input.text().strip(),
            "password": self.password_input.text(),
            "description": self.description_input.toPlainText().strip(),
        }
        save_entries(self.vault_window.key, self.vault_window.entries)
        self.vault_window.refresh_list()
        self.setWindowTitle(title)
        QMessageBox.information(self, "Saved", "Entry saved.")

    def delete_entry(self):
        reply = QMessageBox.question(self, "Delete", f"Delete '{self.entry['title']}'?")
        if reply == QMessageBox.StandardButton.Yes:
            self.vault_window.entries.pop(self.row)
            save_entries(self.vault_window.key, self.vault_window.entries)
            self.vault_window.refresh_list()
            self.close()

# class for adding entries (the actual vault)
class AddEntryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Entry")
        self.setFixedSize(340, 280)
        self.result = None

        layout = QFormLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        self.title_input       = QLineEdit()
        self.username_input    = QLineEdit()
        self.password_input    = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.description_input = QTextEdit()
        self.description_input.setFixedHeight(60)
        self.description_input.setPlaceholderText("Optional description…")

        layout.addRow("Title",       self.title_input)
        layout.addRow("Username",    self.username_input)
        layout.addRow("Password",    self.password_input)
        layout.addRow("Description", self.description_input)

        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save)
        layout.addRow(save_btn)

    def save(self):
        title = self.title_input.text().strip()
        if not title:
            QMessageBox.warning(self, "Error", "Title is required.")
            return
        self.result = {
            "title":       title,
            "username":    self.username_input.text().strip(),
            "password":    self.password_input.text(),
            "description": self.description_input.toPlainText().strip(),
        }
        self.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())