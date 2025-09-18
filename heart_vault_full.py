#!/usr/bin/env python3
# heart_vault_enhanced.py
# Full-featured encrypted personal vault with modern UI
# Dependencies: PyQt6, cryptography
# Install: python -m pip install pyqt6 cryptography

from __future__ import annotations
import sys, os, json, base64, time, secrets, webbrowser
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QDialog, QFormLayout, QMessageBox, QTabWidget,
    QCheckBox, QDateTimeEdit, QStackedWidget, QFrame, QToolButton, QSizePolicy, QScrollArea,
    QButtonGroup, QRadioButton, QGroupBox, QSystemTrayIcon, QMenu, QStyle
)
from PyQt6.QtCore import Qt, QTimer, QEvent, QDateTime, QPropertyAnimation, QEasingCurve, QSize
from PyQt6.QtGui import QClipboard, QIcon, QPixmap, QColor, QPalette, QFont, QAction

VAULT_FILE = "vault.dat"
DEFAULT_ITERATIONS = 250_000
AUTOLOCK_SECONDS = 300
CLIP_TTL = 12
NOTIFY_INTERVAL_MS = 60000  # 1 min check

@dataclass
class Account:
    shortcut: str
    service: str
    url: str
    username: str
    password: str
    notes: str = ""
    tags: List[str] = None
    created_at: float = None
    last_used: Optional[float] = None

    def __post_init__(self):
        if self.tags is None: self.tags = []
        if self.created_at is None: self.created_at = time.time()

@dataclass
class Note:
    title: str
    content: str
    tags: List[str] = None
    created_at: float = None
    last_modified: float = None

    def __post_init__(self):
        if self.tags is None: self.tags = []
        now = time.time()
        if self.created_at is None: self.created_at = now
        if self.last_modified is None: self.last_modified = now

@dataclass
class Todo:
    title: str
    content: str
    tags: List[str] = None
    created_at: float = None
    due_at: float = None
    completed: bool = False

    def __post_init__(self):
        if self.tags is None: self.tags = []
        now = time.time()
        if self.created_at is None: self.created_at = now
        if self.due_at is None: self.due_at = now + 3600  # default 1hr later

# ---------- Crypto ----------
def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def vault_exists(): return os.path.exists(VAULT_FILE)

def read_vault_raw():
    with open(VAULT_FILE, "rb") as f: raw = f.read()
    return json.loads(raw.decode("utf-8"))

def write_vault_raw(obj: Dict[str, Any]):
    with open(VAULT_FILE, "w", encoding="utf-8") as f: json.dump(obj, f)
    try: os.chmod(VAULT_FILE, 0o600)
    except Exception: pass

def create_empty_vault(password: str, iterations: int = DEFAULT_ITERATIONS):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt, iterations)
    f = Fernet(key)
    payload = json.dumps({"accounts":[],"notes":[],"todos":[]}).encode("utf-8")
    ciphertext = f.encrypt(payload)
    out = {"salt": base64.b64encode(salt).decode("utf-8"), "iterations": iterations, "ciphertext": base64.b64encode(ciphertext).decode("utf-8")}
    write_vault_raw(out)

# ---------- Custom Widgets ----------
class FadeWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowOpacity(0)
        
    def fade_in(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(300)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.anim.start()
        
    def fade_out(self):
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(300)
        self.anim.setStartValue(1)
        self.anim.setEndValue(0)
        self.anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.anim.start()

class RoundedButton(QPushButton):
    def __init__(self, text, icon=None, parent=None):
        super().__init__(text, parent)
        self.setFixedHeight(40)
        self.setStyleSheet("""
            QPushButton {
                background-color: #6c5ce7;
                color: white;
                border: none;
                border-radius: 10px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5d4ecd;
            }
            QPushButton:pressed {
                background-color: #4c3cad;
            }
            QPushButton:disabled {
                background-color: #b2bec3;
            }
        """)
        if icon:
            self.setIcon(icon)

# ---------- Dialogs ----------
class CreateVaultDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Vault")
        self.setFixedSize(400, 250)
        layout = QVBoxLayout(self)
        
        title = QLabel("Create Your Secure Vault")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        form = QFormLayout()
        form.setVerticalSpacing(15)
        
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.setPlaceholderText("Enter master password")
        self.pw.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw2.setPlaceholderText("Confirm master password")
        self.pw2.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        form.addRow("Master password:", self.pw)
        form.addRow("Confirm password:", self.pw2)
        layout.addLayout(form)
        
        btns = QHBoxLayout()
        create = RoundedButton("Create Vault")
        create.clicked.connect(self.do_create)
        cancel = RoundedButton("Cancel")
        cancel.clicked.connect(self.reject)
        cancel.setStyleSheet("""
            QPushButton {
                background-color: #dfe6e9;
                color: #2d3436;
            }
            QPushButton:hover {
                background-color: #b2bec3;
            }
        """)
        
        btns.addWidget(create)
        btns.addWidget(cancel)
        layout.addLayout(btns)
        
        self.password=None
        
    def do_create(self):
        p1=self.pw.text().strip(); p2=self.pw2.text().strip()
        if not p1 or p1!=p2: 
            QMessageBox.warning(self,"Error","Passwords must match")
            return
        if len(p1) < 8:
            QMessageBox.warning(self,"Error","Password must be at least 8 characters")
            return
        self.password=p1; self.accept()

class AddAccountDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Account")
        self.setFixedSize(500, 500)
        self.account: Optional[Account] = None
        
        layout = QVBoxLayout(self)
        title = QLabel("Add New Account")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        form = QFormLayout(content)
        form.setVerticalSpacing(15)
        
        self.shortcut = QLineEdit()
        self.shortcut.setPlaceholderText("Unique identifier for quick access")
        self.service = QLineEdit()
        self.service.setPlaceholderText("Service name (e.g., Google, Facebook)")
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://example.com")
        self.username = QLineEdit()
        self.username.setPlaceholderText("Your username or email")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Account password")
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("Comma-separated tags")
        self.notes = QTextEdit()
        self.notes.setPlaceholderText("Additional notes about this account")
        self.notes.setMaximumHeight(100)
        
        for widget in [self.shortcut, self.service, self.url, self.username, self.password, self.tags]:
            widget.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        self.notes.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        form.addRow("Shortcut*:", self.shortcut)
        form.addRow("Service*:", self.service)
        form.addRow("URL:", self.url)
        form.addRow("Username*:", self.username)
        form.addRow("Password*:", self.password)
        form.addRow("Tags:", self.tags)
        form.addRow("Notes:", self.notes)
        
        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        btns = QHBoxLayout()
        save = RoundedButton("Save Account")
        save.clicked.connect(self.do_save)
        cancel = RoundedButton("Cancel")
        cancel.clicked.connect(self.reject)
        cancel.setStyleSheet("""
            QPushButton {
                background-color: #dfe6e9;
                color: #2d3436;
            }
            QPushButton:hover {
                background-color: #b2bec3;
            }
        """)
        
        btns.addWidget(save)
        btns.addWidget(cancel)
        layout.addLayout(btns)

    def do_save(self):
        sh = self.shortcut.text().strip()
        svc = self.service.text().strip()
        user = self.username.text().strip()
        pw = self.password.text().strip()
        if not sh or not svc or not user or not pw:
            QMessageBox.warning(self, "Missing", "Fields marked with * are required")
            return
        tags = [t.strip() for t in self.tags.text().split(',') if t.strip()]
        self.account = Account(
            shortcut=sh, 
            service=svc, 
            url=self.url.text().strip(),
            username=user, 
            password=pw, 
            notes=self.notes.toPlainText(), 
            tags=tags
        )
        self.accept()

class AddNoteDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Note")
        self.setFixedSize(500, 400)
        self.note: Optional[Note] = None
        
        layout = QVBoxLayout(self)
        title = QLabel("Add New Note")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        form = QFormLayout()
        form.setVerticalSpacing(15)
        
        self.title = QLineEdit()
        self.title.setPlaceholderText("Note title")
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("Comma-separated tags")
        self.content = QTextEdit()
        self.content.setPlaceholderText("Your note content")
        
        for widget in [self.title, self.tags]:
            widget.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        self.content.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        form.addRow("Title*:", self.title)
        form.addRow("Tags:", self.tags)
        form.addRow("Content*:", self.content)
        layout.addLayout(form)
        
        btns = QHBoxLayout()
        save = RoundedButton("Save Note")
        save.clicked.connect(self.do_save)
        cancel = RoundedButton("Cancel")
        cancel.clicked.connect(self.reject)
        cancel.setStyleSheet("""
            QPushButton {
                background-color: #dfe6e9;
                color: #2d3436;
            }
            QPushButton:hover {
                background-color: #b2bec3;
            }
        """)
        
        btns.addWidget(save)
        btns.addWidget(cancel)
        layout.addLayout(btns)

    def do_save(self):
        title = self.title.text().strip()
        content = self.content.toPlainText().strip()
        if not title or not content:
            QMessageBox.warning(self, "Missing", "Title and content are required")
            return
        tags = [t.strip() for t in self.tags.text().split(',') if t.strip()]
        self.note = Note(title=title, content=content, tags=tags)
        self.accept()

class AddTodoDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Todo")
        self.setFixedSize(500, 450)
        self.todo: Optional[Todo] = None
        
        layout = QVBoxLayout(self)
        title = QLabel("Add New Todo")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        form = QFormLayout()
        form.setVerticalSpacing(15)
        
        self.title = QLineEdit()
        self.title.setPlaceholderText("Todo title")
        self.tags = QLineEdit()
        self.tags.setPlaceholderText("Comma-separated tags")
        self.due_date = QDateTimeEdit()
        self.due_date.setDateTime(QDateTime.currentDateTime().addDays(1))
        self.content = QTextEdit()
        self.content.setPlaceholderText("Todo details")
        
        for widget in [self.title, self.tags]:
            widget.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        self.content.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        form.addRow("Title*:", self.title)
        form.addRow("Tags:", self.tags)
        form.addRow("Due Date:", self.due_date)
        form.addRow("Details:", self.content)
        layout.addLayout(form)
        
        btns = QHBoxLayout()
        save = RoundedButton("Save Todo")
        save.clicked.connect(self.do_save)
        cancel = RoundedButton("Cancel")
        cancel.clicked.connect(self.reject)
        cancel.setStyleSheet("""
            QPushButton {
                background-color: #dfe6e9;
                color: #2d3436;
            }
            QPushButton:hover {
                background-color: #b2bec3;
            }
        """)
        
        btns.addWidget(save)
        btns.addWidget(cancel)
        layout.addLayout(btns)

    def do_save(self):
        title = self.title.text().strip()
        content = self.content.toPlainText().strip()
        if not title:
            QMessageBox.warning(self, "Missing", "Title is required")
            return
        tags = [t.strip() for t in self.tags.text().split(',') if t.strip()]
        due_at = self.due_date.dateTime().toSecsSinceEpoch()
        self.todo = Todo(title=title, content=content, tags=tags, due_at=due_at)
        self.accept()

# ---------- Tab Widgets ----------
class BaseTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.vault = parent
        self.current_item = None
        
    def refresh_data(self):
        raise NotImplementedError("Subclasses must implement refresh_data")
        
    def clear_selection(self):
        raise NotImplementedError("Subclasses must implement clear_selection")

class AccountsTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Left panel - list
        left_panel = QVBoxLayout()
        left_panel.setContentsMargins(0, 0, 0, 0)
        
        # Search and controls
        controls = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search accounts...")
        self.search_input.textChanged.connect(self.filter_list)
        self.search_input.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        self.add_btn = QToolButton()
        self.add_btn.setText("+ Add")
        self.add_btn.setStyleSheet("QToolButton { padding: 8px; border-radius: 5px; background-color: #6c5ce7; color: white; }")
        self.add_btn.clicked.connect(self.add_account)
        
        controls.addWidget(self.search_input)
        controls.addWidget(self.add_btn)
        left_panel.addLayout(controls)
        
        # Account list
        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.on_item_clicked)
        self.list_widget.setStyleSheet("""
            QListWidget {
                border: 1px solid #ddd;
                border-radius: 5px;
                background-color: white;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #eee;
            }
            QListWidget::item:selected {
                background-color: #f0f0f0;
                color: #333;
            }
        """)
        left_panel.addWidget(self.list_widget)
        
        # Right panel - details
        right_panel = QVBoxLayout()
        self.detail_frame = QFrame()
        self.detail_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 15px;
            }
        """)
        detail_layout = QVBoxLayout(self.detail_frame)
        
        self.detail_title = QLabel("Select an account to view details")
        self.detail_title.setStyleSheet("font-weight: bold; font-size: 16px; margin-bottom: 15px;")
        self.detail_title.setWordWrap(True)
        
        self.detail_content = QTextEdit()
        self.detail_content.setReadOnly(True)
        self.detail_content.setStyleSheet("border: 1px solid #eee; border-radius: 5px; padding: 10px;")
        
        # Action buttons
        action_layout = QHBoxLayout()
        self.copy_user_btn = RoundedButton("Copy Username")
        self.copy_user_btn.clicked.connect(self.copy_username)
        self.copy_pass_btn = RoundedButton("Copy Password")
        self.copy_pass_btn.clicked.connect(self.copy_password)
        self.reveal_btn = RoundedButton("Reveal Password")
        self.reveal_btn.clicked.connect(self.reveal_password)
        self.open_url_btn = RoundedButton("Open URL")
        self.open_url_btn.clicked.connect(self.open_url)
        
        action_layout.addWidget(self.copy_user_btn)
        action_layout.addWidget(self.copy_pass_btn)
        action_layout.addWidget(self.reveal_btn)
        action_layout.addWidget(self.open_url_btn)
        
        detail_layout.addWidget(self.detail_title)
        detail_layout.addWidget(self.detail_content)
        detail_layout.addLayout(action_layout)
        
        right_panel.addWidget(self.detail_frame)
        
        layout.addLayout(left_panel, 2)
        layout.addLayout(right_panel, 3)
        
        self.clear_selection()
        
    def refresh_data(self):
        self.list_widget.clear()
        for account in self.vault._data.get("accounts", []):
            item = QListWidgetItem(f"{account.get('shortcut', '')} — {account.get('service', '')}")
            item.setData(Qt.ItemDataRole.UserRole, account)
            self.list_widget.addItem(item)
            
    def filter_list(self):
        query = self.search_input.text().lower()
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            account = item.data(Qt.ItemDataRole.UserRole)
            match = (query in account.get('shortcut', '').lower() or 
                    query in account.get('service', '').lower() or
                    query in account.get('username', '').lower() or
                    any(query in tag.lower() for tag in account.get('tags', [])))
            item.setHidden(not match)
            
    def on_item_clicked(self, item):
        account = item.data(Qt.ItemDataRole.UserRole)
        self.current_item = account
        self.detail_title.setText(f"{account.get('service', '')} — {account.get('shortcut', '')}")
        
        details = f"""
        <b>URL:</b> {account.get('url', 'None')}<br><br>
        <b>Username:</b> {account.get('username', '')}<br><br>
        <b>Password:</b> {'*' * 12}<br><br>
        <b>Tags:</b> {', '.join(account.get('tags', [])) or 'None'}<br><br>
        <b>Notes:</b><br>{account.get('notes', 'None')}
        """
        self.detail_content.setHtml(details)
        
        # Enable buttons
        for btn in [self.copy_user_btn, self.copy_pass_btn, self.reveal_btn]:
            btn.setEnabled(True)
        self.open_url_btn.setEnabled(bool(account.get('url')))
        
    def clear_selection(self):
        self.current_item = None
        self.detail_title.setText("Select an account to view details")
        self.detail_content.clear()
        for btn in [self.copy_user_btn, self.copy_pass_btn, self.reveal_btn, self.open_url_btn]:
            btn.setEnabled(False)
            
    def add_account(self):
        dlg = AddAccountDialog(self)
        if dlg.exec() and dlg.account:
            account_dict = asdict(dlg.account)
            self.vault._data.setdefault('accounts', []).append(account_dict)
            self.vault.write_encrypted()
            self.refresh_data()
            QMessageBox.information(self, "Success", "Account added successfully")
            
    def copy_username(self):
        if not self.current_item: return
        username = self.current_item.get('username', '')
        QApplication.clipboard().setText(username)
        self.vault.clip_timer.start(CLIP_TTL * 1000)
        QMessageBox.information(self, "Copied", f"Username copied to clipboard (will clear in {CLIP_TTL}s)")
        
    def copy_password(self):
        if not self.current_item: return
        password = self.current_item.get('password', '')
        QApplication.clipboard().setText(password)
        self.vault.clip_timer.start(CLIP_TTL * 1000)
        QMessageBox.information(self, "Copied", f"Password copied to clipboard (will clear in {CLIP_TTL}s)")
        
    def reveal_password(self):
        if not self.current_item: return
        password = self.current_item.get('password', '')
        QMessageBox.information(self, "Password", f"Password: {password}")
        
    def open_url(self):
        if not self.current_item: return
        url = self.current_item.get('url', '')
        if url:
            webbrowser.open(url)

class NotesTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Left panel - list
        left_panel = QVBoxLayout()
        left_panel.setContentsMargins(0, 0, 0, 0)
        
        # Search and controls
        controls = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search notes...")
        self.search_input.textChanged.connect(self.filter_list)
        self.search_input.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        self.add_btn = QToolButton()
        self.add_btn.setText("+ Add")
        self.add_btn.setStyleSheet("QToolButton { padding: 8px; border-radius: 5px; background-color: #6c5ce7; color: white; }")
        self.add_btn.clicked.connect(self.add_note)
        
        controls.addWidget(self.search_input)
        controls.addWidget(self.add_btn)
        left_panel.addLayout(controls)
        
        # Notes list
        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.on_item_clicked)
        self.list_widget.setStyleSheet("""
            QListWidget {
                border: 1px solid #ddd;
                border-radius: 5px;
                background-color: white;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #eee;
            }
            QListWidget::item:selected {
                background-color: #f0f0f0;
                color: #333;
            }
        """)
        left_panel.addWidget(self.list_widget)
        
        # Right panel - details
        right_panel = QVBoxLayout()
        self.detail_frame = QFrame()
        self.detail_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 15px;
            }
        """)
        detail_layout = QVBoxLayout(self.detail_frame)
        
        self.detail_title = QLabel("Select a note to view details")
        self.detail_title.setStyleSheet("font-weight: bold; font-size: 16px; margin-bottom: 15px;")
        self.detail_title.setWordWrap(True)
        
        self.detail_content = QTextEdit()
        self.detail_content.setReadOnly(True)
        self.detail_content.setStyleSheet("border: 1px solid #eee; border-radius: 5px; padding: 10px;")
        
        detail_layout.addWidget(self.detail_title)
        detail_layout.addWidget(self.detail_content)
        
        right_panel.addWidget(self.detail_frame)
        
        layout.addLayout(left_panel, 2)
        layout.addLayout(right_panel, 3)
        
        self.clear_selection()
        
    def refresh_data(self):
        self.list_widget.clear()
        for note in self.vault._data.get("notes", []):
            item = QListWidgetItem(note.get('title', 'Untitled'))
            item.setData(Qt.ItemDataRole.UserRole, note)
            self.list_widget.addItem(item)
            
    def filter_list(self):
        query = self.search_input.text().lower()
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            note = item.data(Qt.ItemDataRole.UserRole)
            match = (query in note.get('title', '').lower() or 
                    query in note.get('content', '').lower() or
                    any(query in tag.lower() for tag in note.get('tags', [])))
            item.setHidden(not match)
            
    def on_item_clicked(self, item):
        note = item.data(Qt.ItemDataRole.UserRole)
        self.current_item = note
        self.detail_title.setText(note.get('title', 'Untitled'))
        
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(note.get('created_at', 0)))
        modified = time.strftime("%Y-%m-%d %H:%M", time.localtime(note.get('last_modified', 0)))
        
        details = f"""
        <b>Created:</b> {created}<br>
        <b>Modified:</b> {modified}<br>
        <b>Tags:</b> {', '.join(note.get('tags', [])) or 'None'}<br><br>
        <b>Content:</b><br>{note.get('content', '')}
        """
        self.detail_content.setHtml(details)
        
    def clear_selection(self):
        self.current_item = None
        self.detail_title.setText("Select a note to view details")
        self.detail_content.clear()
            
    def add_note(self):
        dlg = AddNoteDialog(self)
        if dlg.exec() and dlg.note:
            note_dict = asdict(dlg.note)
            self.vault._data.setdefault('notes', []).append(note_dict)
            self.vault.write_encrypted()
            self.refresh_data()
            QMessageBox.information(self, "Success", "Note added successfully")

class TodosTab(BaseTab):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Left panel - list
        left_panel = QVBoxLayout()
        left_panel.setContentsMargins(0, 0, 0, 0)
        
        # Filter options
        filter_group = QGroupBox("Filter")
        filter_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        filter_layout = QVBoxLayout(filter_group)
        
        self.filter_all = QRadioButton("All")
        self.filter_active = QRadioButton("Active")
        self.filter_completed = QRadioButton("Completed")
        
        self.filter_all.setChecked(True)
        self.filter_all.toggled.connect(self.refresh_data)
        self.filter_active.toggled.connect(self.refresh_data)
        self.filter_completed.toggled.connect(self.refresh_data)
        
        filter_layout.addWidget(self.filter_all)
        filter_layout.addWidget(self.filter_active)
        filter_layout.addWidget(self.filter_completed)
        left_panel.addWidget(filter_group)
        
        # Search and controls
        controls = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search todos...")
        self.search_input.textChanged.connect(self.filter_list)
        self.search_input.setStyleSheet("padding: 8px; border-radius: 5px; border: 1px solid #ddd;")
        
        self.add_btn = QToolButton()
        self.add_btn.setText("+ Add")
        self.add_btn.setStyleSheet("QToolButton { padding: 8px; border-radius: 5px; background-color: #6c5ce7; color: white; }")
        self.add_btn.clicked.connect(self.add_todo)
        
        controls.addWidget(self.search_input)
        controls.addWidget(self.add_btn)
        left_panel.addLayout(controls)
        
        # Todos list
        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.on_item_clicked)
        self.list_widget.setStyleSheet("""
            QListWidget {
                border: 1px solid #ddd;
                border-radius: 5px;
                background-color: white;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #eee;
            }
            QListWidget::item:selected {
                background-color: #f0f0f0;
                color: #333;
            }
        """)
        left_panel.addWidget(self.list_widget)
        
        # Right panel - details
        right_panel = QVBoxLayout()
        self.detail_frame = QFrame()
        self.detail_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 15px;
            }
        """)
        detail_layout = QVBoxLayout(self.detail_frame)
        
        self.detail_title = QLabel("Select a todo to view details")
        self.detail_title.setStyleSheet("font-weight: bold; font-size: 16px; margin-bottom: 15px;")
        self.detail_title.setWordWrap(True)
        
        self.detail_content = QTextEdit()
        self.detail_content.setReadOnly(True)
        self.detail_content.setStyleSheet("border: 1px solid #eee; border-radius: 5px; padding: 10px;")
        
        # Action buttons
        action_layout = QHBoxLayout()
        self.complete_btn = RoundedButton("Mark Complete")
        self.complete_btn.clicked.connect(self.toggle_complete)
        
        action_layout.addWidget(self.complete_btn)
        
        detail_layout.addWidget(self.detail_title)
        detail_layout.addWidget(self.detail_content)
        detail_layout.addLayout(action_layout)
        
        right_panel.addWidget(self.detail_frame)
        
        layout.addLayout(left_panel, 2)
        layout.addLayout(right_panel, 3)
        
        self.clear_selection()
        
    def refresh_data(self):
        self.list_widget.clear()
        for todo in self.vault._data.get("todos", []):
            # Apply filter
            if self.filter_active.isChecked() and todo.get('completed', False):
                continue
            if self.filter_completed.isChecked() and not todo.get('completed', False):
                continue
                
            title = todo.get('title', 'Untitled')
            if todo.get('completed', False):
                title = f"✓ {title}"
                
            item = QListWidgetItem(title)
            item.setData(Qt.ItemDataRole.UserRole, todo)
            
            # Color code based on due date and completion
            due_at = todo.get('due_at', 0)
            if todo.get('completed', False):
                item.setForeground(QColor("#27ae60"))  # Green for completed
            elif due_at < time.time():
                item.setForeground(QColor("#e74c3c"))  # Red for overdue
            elif due_at < time.time() + 86400:  # Due within 24 hours
                item.setForeground(QColor("#f39c12"))  # Orange for due soon
                
            self.list_widget.addItem(item)
            
    def filter_list(self):
        query = self.search_input.text().lower()
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            todo = item.data(Qt.ItemDataRole.UserRole)
            match = (query in todo.get('title', '').lower() or 
                    query in todo.get('content', '').lower() or
                    any(query in tag.lower() for tag in todo.get('tags', [])))
            item.setHidden(not match)
            
    def on_item_clicked(self, item):
        todo = item.data(Qt.ItemDataRole.UserRole)
        self.current_item = todo
        self.detail_title.setText(todo.get('title', 'Untitled'))
        
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(todo.get('created_at', 0)))
        due = time.strftime("%Y-%m-%d %H:%M", time.localtime(todo.get('due_at', 0)))
        status = "Completed" if todo.get('completed', False) else "Active"
        
        details = f"""
        <b>Status:</b> {status}<br>
        <b>Created:</b> {created}<br>
        <b>Due:</b> {due}<br>
        <b>Tags:</b> {', '.join(todo.get('tags', [])) or 'None'}<br><br>
        <b>Details:</b><br>{todo.get('content', '')}
        """
        self.detail_content.setHtml(details)
        
        # Update complete button text
        if todo.get('completed', False):
            self.complete_btn.setText("Mark Incomplete")
        else:
            self.complete_btn.setText("Mark Complete")
        self.complete_btn.setEnabled(True)
        
    def clear_selection(self):
        self.current_item = None
        self.detail_title.setText("Select a todo to view details")
        self.detail_content.clear()
        self.complete_btn.setEnabled(False)
            
    def add_todo(self):
        dlg = AddTodoDialog(self)
        if dlg.exec() and dlg.todo:
            todo_dict = asdict(dlg.todo)
            self.vault._data.setdefault('todos', []).append(todo_dict)
            self.vault.write_encrypted()
            self.refresh_data()
            QMessageBox.information(self, "Success", "Todo added successfully")
            
    def toggle_complete(self):
        if not self.current_item: return
        
        # Find the todo in the data and update it
        for todo in self.vault._data.get("todos", []):
            if (todo.get('title') == self.current_item.get('title') and 
                todo.get('created_at') == self.current_item.get('created_at')):
                todo['completed'] = not todo.get('completed', False)
                break
                
        self.vault.write_encrypted()
        self.refresh_data()
        self.clear_selection()

# ---------- Main Vault App ----------
class HeartVault(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("💖 Heart Vault - Your Secure Personal Vault")
        self.resize(1200, 800)
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
                background-color: #f5f6fa;
            }
            QTabWidget::pane {
                border: 1px solid #dcdde1;
                background: white;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #f5f6fa;
                border: 1px solid #dcdde1;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: white;
                border-bottom-color: white;
            }
        """)
        
        self._key = None
        self._data: Dict[str, Any] = {"accounts":[],"notes":[],"todos":[]}
        self._iterations = DEFAULT_ITERATIONS
        self._salt = None

        self.clip_timer = QTimer(self)
        self.clip_timer.setSingleShot(True)
        self.clip_timer.timeout.connect(self.clear_clipboard)

        self.autolock_timer = QTimer(self)
        self.autolock_timer.setSingleShot(True)
        self.autolock_timer.timeout.connect(self.auto_lock)

        self.notify_timer = QTimer(self)
        self.notify_timer.timeout.connect(self.check_todos)
        self.notify_timer.start(NOTIFY_INTERVAL_MS)

        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self.update_clock)
        self.clock_timer.start(1000)

        self.setup_ui()
        self.installEventFilter(self)
        
        # System tray
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        
        tray_menu = QMenu()
        show_action = tray_menu.addAction("Show")
        show_action.triggered.connect(self.show)
        lock_action = tray_menu.addAction("Lock")
        lock_action.triggered.connect(self.lock_vault)
        quit_action = tray_menu.addAction("Quit")
        quit_action.triggered.connect(QApplication.quit)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        self.setLayout(layout)

        # Header
        header = QHBoxLayout()
        title = QLabel("💖 Heart Vault")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #6c5ce7;")
        
        self.clock_label = QLabel()
        self.clock_label.setStyleSheet("color: #636e72; font-size: 14px;")
        self.update_clock()
        
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.clock_label)
        layout.addLayout(header)

        # Stack for login/main views
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        # Login widget
        self.login_widget = QWidget()
        login_layout = QVBoxLayout(self.login_widget)
        login_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_layout.setContentsMargins(50, 50, 50, 50)
        
        login_card = QFrame()
        login_card.setStyleSheet("""
            QFrame {
                background-color: white;
                border-radius: 10px;
                padding: 30px;
                border: 1px solid #ddd;
            }
        """)
        login_card_layout = QVBoxLayout(login_card)
        
        login_title = QLabel("Unlock Your Vault")
        login_title.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 20px;")
        login_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        login_card_layout.addWidget(login_title)
        
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_input.setPlaceholderText("Master password")
        self.pw_input.setStyleSheet("padding: 12px; border-radius: 8px; border: 1px solid #ddd; font-size: 14px;")
        self.pw_input.returnPressed.connect(self.handle_unlock)
        login_card_layout.addWidget(self.pw_input)
        
        btn_layout = QHBoxLayout()
        btn_unlock = RoundedButton("Unlock")
        btn_unlock.clicked.connect(self.handle_unlock)
        btn_create = RoundedButton("Create New Vault")
        btn_create.clicked.connect(self.show_create)
        btn_create.setStyleSheet("""
            QPushButton {
                background-color: #dfe6e9;
                color: #2d3436;
            }
            QPushButton:hover {
                background-color: #b2bec3;
            }
        """)
        
        btn_layout.addWidget(btn_unlock)
        btn_layout.addWidget(btn_create)
        login_card_layout.addLayout(btn_layout)
        
        login_layout.addWidget(login_card)
        self.stack.addWidget(self.login_widget)

        # Main widget with tabs
        self.main_widget = QWidget()
        main_layout = QVBoxLayout(self.main_widget)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #dcdde1;
                background: white;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #f5f6fa;
                border: 1px solid #dcdde1;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QTabBar::tab:selected {
                background: white;
                border-bottom-color: white;
            }
        """)
        
        # Create tabs
        self.accounts_tab = AccountsTab(self)
        self.notes_tab = NotesTab(self)
        self.todos_tab = TodosTab(self)
        
        self.tabs.addTab(self.accounts_tab, "🔐 Accounts")
        self.tabs.addTab(self.notes_tab, "📝 Notes")
        self.tabs.addTab(self.todos_tab, "✅ Todos")
        
        # Status bar
        status_bar = QHBoxLayout()
        status_bar.addStretch()
        self.lock_btn = RoundedButton("Lock Vault")
        self.lock_btn.clicked.connect(self.lock_vault)
        self.lock_btn.setStyleSheet("""
            QPushButton {
                background-color: #fd79a8;
                color: white;
            }
            QPushButton:hover {
                background-color: #e84393;
            }
        """)
        status_bar.addWidget(self.lock_btn)
        
        main_layout.addWidget(self.tabs)
        main_layout.addLayout(status_bar)
        self.stack.addWidget(self.main_widget)

        if vault_exists():
            self.stack.setCurrentWidget(self.login_widget)
        else:
            self.show_create()

    def update_clock(self):
        self.clock_label.setText(time.strftime("%A, %d %B %Y %H:%M:%S"))

    def show_create(self):
        dlg = CreateVaultDialog(self)
        if dlg.exec():
            create_empty_vault(dlg.password)
            QMessageBox.information(self, "Vault Created", "Heart Vault initialized. Unlock to begin.")
            self.stack.setCurrentWidget(self.login_widget)

    def handle_unlock(self):
        pw = self.pw_input.text().strip()
        if not pw: 
            QMessageBox.warning(self,"Error","Enter master password")
            return
        if not vault_exists(): 
            QMessageBox.warning(self,"Error","No vault found. Create one first.")
            return
        try:
            obj = read_vault_raw()
            salt = base64.b64decode(obj["salt"])
            iterations = int(obj.get("iterations", DEFAULT_ITERATIONS))
            ciphertext = base64.b64decode(obj["ciphertext"])
        except Exception:
            QMessageBox.critical(self,"Error","Vault corrupted")
            return
        key = derive_key(pw, salt, iterations)
        f = Fernet(key)
        try:
            plaintext = f.decrypt(ciphertext)
            self._data = json.loads(plaintext.decode("utf-8"))
            self._key = key
            self._salt = salt
            self._iterations = iterations
            
            # Refresh all tabs
            self.accounts_tab.refresh_data()
            self.notes_tab.refresh_data()
            self.todos_tab.refresh_data()
            
            self.stack.setCurrentWidget(self.main_widget)
            self.reset_autolock()
        except InvalidToken:
            QMessageBox.critical(self,"Error","Incorrect password")
            
    def lock_vault(self):
        self._key = None
        self._data = {"accounts":[],"notes":[],"todos":[]}
        self.accounts_tab.clear_selection()
        self.notes_tab.clear_selection()
        self.todos_tab.clear_selection()
        self.stack.setCurrentWidget(self.login_widget)
        self.pw_input.clear()
        QMessageBox.information(self, "Locked", "Vault locked")
        
    def reset_autolock(self):
        self.autolock_timer.stop()
        self.autolock_timer.start(AUTOLOCK_SECONDS * 1000)

    def auto_lock(self):
        self.lock_vault()
        QMessageBox.information(self,"Auto-lock","Vault auto-locked due to inactivity")

    def clear_clipboard(self):
        QApplication.clipboard().clear(mode=QClipboard.Mode.Clipboard)

    def check_todos(self):
        if not self._key: 
            return
            
        now = time.time()
        for todo in self._data.get('todos',[]):
            if not todo.get('completed',False) and todo.get('due_at',0) <= now:
                self.tray_icon.showMessage(
                    "TODO Reminder", 
                    f"'{todo.get('title')}' is due!",
                    QSystemTrayIcon.MessageIcon.Information,
                    5000
                )
                
    def write_encrypted(self):
        if not self._key or self._salt is None:
            raise RuntimeError("Vault not unlocked")
        f = Fernet(self._key)
        payload = json.dumps(self._data).encode("utf-8")
        ciphertext = f.encrypt(payload)
        out = {
            "salt": base64.b64encode(self._salt).decode("utf-8"),
            "iterations": self._iterations,
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }
        write_vault_raw(out)
        
    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress):
            if self._key:
                self.reset_autolock()
        return super().eventFilter(obj, event)
        
    def closeEvent(self, event):
        if self._key:
            reply = QMessageBox.question(
                self, 
                "Confirm Exit", 
                "Vault is unlocked. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

# ---------- Main ----------
def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set application style
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(245, 246, 250))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(33, 33, 33))
    palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(33, 33, 33))
    palette.setColor(QPalette.ColorRole.Text, QColor(33, 33, 33))
    palette.setColor(QPalette.ColorRole.Button, QColor(245, 246, 250))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(33, 33, 33))
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(palette)
    
    window = HeartVault()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()