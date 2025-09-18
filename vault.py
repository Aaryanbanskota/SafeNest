#!/usr/bin/env python3
# vault_desktop.py
# Single-file PyQt6 encrypted vault app (Python 3.17.7)
# Dependencies: PyQt6, cryptography
# Install: python -m pip install pyqt6 cryptography

from __future__ import annotations
import sys
import os
import json
import base64
import time
import secrets
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import webbrowser

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QDialog, QFormLayout, QMessageBox, QStackedWidget,
    QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QEvent
from PyQt6.QtGui import QClipboard

VAULT_FILE = "vault.dat"
DEFAULT_ITERATIONS = 250_000
AUTOLOCK_SECONDS = 300  # auto-lock after 5 minutes
CLIP_TTL = 12  # seconds to keep clipboard


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
        if self.tags is None:
            self.tags = []
        if self.created_at is None:
            self.created_at = time.time()


# ---------- crypto helpers ----------

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def vault_exists() -> bool:
    return os.path.exists(VAULT_FILE)


def read_vault_raw() -> Dict[str, Any]:
    with open(VAULT_FILE, "rb") as f:
        raw = f.read()
    return json.loads(raw.decode("utf-8"))


def write_vault_raw(obj: Dict[str, Any]):
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    try:
        os.chmod(VAULT_FILE, 0o600)
    except Exception:
        pass


def create_empty_vault(password: str, iterations: int = DEFAULT_ITERATIONS):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt, iterations)
    f = Fernet(key)
    payload = json.dumps({"accounts": []}).encode("utf-8")
    ciphertext = f.encrypt(payload)
    out = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iterations": iterations,
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    write_vault_raw(out)


# ---------- Qt Application ----------
class VaultApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Shortcut Vault")
        self.resize(900, 620)
        self._key = None
        self._data: Dict[str, Any] = {"accounts": []}
        self._iterations = DEFAULT_ITERATIONS
        self._salt = None
        self.current_account = None

        self.clip_timer = QTimer(self)
        self.clip_timer.setSingleShot(True)
        self.clip_timer.timeout.connect(self.clear_clipboard)

        self.autolock_timer = QTimer(self)
        self.autolock_timer.setSingleShot(True)
        self.autolock_timer.timeout.connect(self.auto_lock)

        self.setup_ui()
        self.installEventFilter(self)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        # header
        header = QHBoxLayout()
        title = QLabel("<h2>🔐 Shortcut Vault</h2>")
        subtitle = QLabel("Encrypted local vault — run locally. No auto-login.")
        subtitle.setStyleSheet("color: #9aa4b2;")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(subtitle)
        layout.addLayout(header)

        # stacked views
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)

        self.login_widget = self.make_login_widget()
        self.main_widget = self.make_main_widget()

        self.stack.addWidget(self.login_widget)
        self.stack.addWidget(self.main_widget)

        if vault_exists():
            self.show_login()
        else:
            self.show_create()

    # ---------- UI components ----------
    def make_login_widget(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setAlignment(Qt.AlignmentFlag.AlignTop)

        info = QLabel("Enter master password to unlock the vault")
        info.setStyleSheet("font-size:14px;")
        v.addWidget(info)

        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        v.addWidget(self.pw_input)

        h = QHBoxLayout()
        btn_unlock = QPushButton("Unlock")
        btn_unlock.clicked.connect(self.handle_unlock)
        h.addWidget(btn_unlock)

        btn_create = QPushButton("Create Vault")
        btn_create.clicked.connect(self.show_create)
        h.addWidget(btn_create)

        v.addLayout(h)
        return w

    def make_main_widget(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)

        # left: list + controls
        left = QVBoxLayout()
        controls = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search shortcuts or services")
        self.search_input.textChanged.connect(self.render_list)
        controls.addWidget(self.search_input)
        btn_add = QPushButton("+ Add")
        btn_add.clicked.connect(self.add_dialog)
        controls.addWidget(btn_add)
        btn_lock = QPushButton("Lock")
        btn_lock.clicked.connect(self.lock_vault)
        controls.addWidget(btn_lock)
        left.addLayout(controls)

        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.on_item_clicked)
        left.addWidget(self.list_widget)

        h.addLayout(left, 2)

        # right: details
        right = QVBoxLayout()
        self.detail_title = QLabel("Select an account")
        self.detail_title.setStyleSheet("font-weight:700;font-size:16px;")
        right.addWidget(self.detail_title)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        right.addWidget(self.detail_text)

        actions = QHBoxLayout()
        btn_copy_user = QPushButton("Copy username")
        btn_copy_user.clicked.connect(self.copy_username)
        actions.addWidget(btn_copy_user)
        btn_copy_pass = QPushButton("Copy password")
        btn_copy_pass.clicked.connect(self.copy_password)
        actions.addWidget(btn_copy_pass)
        btn_reveal = QPushButton("Reveal password")
        btn_reveal.clicked.connect(self.reveal_password)
        actions.addWidget(btn_reveal)
        btn_open = QPushButton("Open URL")
        btn_open.clicked.connect(self.open_url)
        actions.addWidget(btn_open)
        right.addLayout(actions)

        theme_h = QHBoxLayout()
        self.theme_cb = QCheckBox("Light theme")
        theme_h.addWidget(self.theme_cb)
        right.addLayout(theme_h)

        h.addLayout(right, 3)
        return w

    # ---------- view management ----------
    def show_login(self):
        self.stack.setCurrentWidget(self.login_widget)
        self.animate_fade(self.login_widget)

    def show_create(self):
        dlg = CreateVaultDialog(self)
        if dlg.exec():
            pw = dlg.password
            create_empty_vault(pw)
            QMessageBox.information(self, "Vault created", "Vault initialized — please unlock.")
            self.show_login()

    def show_main(self):
        self.stack.setCurrentWidget(self.main_widget)
        self.animate_fade(self.main_widget)
        self.render_list()
        self.reset_autolock()

    def animate_fade(self, widget: QWidget):
        widget.setWindowOpacity(0)
        anim = QPropertyAnimation(widget, b"windowOpacity")
        anim.setDuration(320)
        anim.setStartValue(0)
        anim.setEndValue(1)
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        anim.start()
        self._last_anim = anim  # keep reference

    # ---------- vault operations ----------
    def handle_unlock(self):
        pw = self.pw_input.text().strip()
        if not pw:
            QMessageBox.warning(self, "Error", "Enter master password")
            return
        if not vault_exists():
            QMessageBox.warning(self, "Error", "No vault found. Create one first.")
            return
        try:
            obj = read_vault_raw()
            salt = base64.b64decode(obj["salt"])
            iterations = int(obj.get("iterations", DEFAULT_ITERATIONS))
            ciphertext = base64.b64decode(obj["ciphertext"])
        except Exception:
            QMessageBox.critical(self, "Error", "Vault file corrupted or unreadable")
            return
        key = derive_key(pw, salt, iterations)
        f = Fernet(key)
        try:
            plaintext = f.decrypt(ciphertext)
            payload = json.loads(plaintext.decode("utf-8"))
            self._key = key
            self._data = payload
            self._iterations = iterations
            self._salt = salt
            self.show_main()
        except InvalidToken:
            QMessageBox.critical(self, "Error", "Incorrect master password")

    def lock_vault(self):
        self._key = None
        self._data = {"accounts": []}
        self.list_widget.clear()
        self.detail_text.clear()
        self.detail_title.setText("Locked")
        self.stack.setCurrentWidget(self.login_widget)
        QMessageBox.information(self, "Locked", "Vault locked")

    def reset_autolock(self):
        self.autolock_timer.stop()
        self.autolock_timer.start(AUTOLOCK_SECONDS * 1000)

    def auto_lock(self):
        QMessageBox.information(self, "Auto-lock", "Vault auto-locked due to inactivity")
        self.lock_vault()

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

    # ---------- list & detail ----------
    def render_list(self):
        self.list_widget.clear()
        q = self.search_input.text().strip().lower()
        for a in self._data.get("accounts", []):
            if q and q not in a.get("shortcut", "").lower() and q not in a.get("service", "").lower():
                continue
            item = QListWidgetItem(f"{a.get('shortcut')} — {a.get('service')}")
            item.setData(Qt.ItemDataRole.UserRole, a)
            self.list_widget.addItem(item)

    def on_item_clicked(self, item: QListWidgetItem):
        a = item.data(Qt.ItemDataRole.UserRole)
        self.current_account = a
        self.detail_title.setText(f"{a.get('service')} — {a.get('shortcut')}")
        txt = f"URL: {a.get('url') or '-'}\nUsername: {a.get('username')}\nPassword: {'*'*8}\nTags: {', '.join(a.get('tags', []))}\nNotes: {a.get('notes','')}"
        self.detail_text.setPlainText(txt)
        a['last_used'] = time.time()
        self.write_encrypted()
        self.reset_autolock()

    def copy_username(self):
        if not self.current_account:
            QMessageBox.information(self, "Info", "Select an account first")
            return
        val = self.current_account.get('username')
        QApplication.clipboard().setText(val, mode=QClipboard.Mode.Clipboard)
        self.clip_timer.start(CLIP_TTL * 1000)
        QMessageBox.information(self, "Copied", f"Username copied — will clear in {CLIP_TTL}s")
        self.reset_autolock()

    def copy_password(self):
        if not self.current_account:
            QMessageBox.information(self, "Info", "Select an account first")
            return
        val = self.current_account.get('password')
        QApplication.clipboard().setText(val, mode=QClipboard.Mode.Clipboard)
        self.clip_timer.start(CLIP_TTL * 1000)
        QMessageBox.information(self, "Copied", f"Password copied — will clear in {CLIP_TTL}s")
        self.reset_autolock()

    def clear_clipboard(self):
        QApplication.clipboard().clear(mode=QClipboard.Mode.Clipboard)

    def reveal_password(self):
        if not self.current_account:
            QMessageBox.information(self, "Info", "Select an account first")
            return
        val = self.current_account.get('password')
        QMessageBox.information(self, "Password", f"{val}")
        self.reset_autolock()

    def open_url(self):
        if not self.current_account:
            QMessageBox.information(self, "Info", "Select an account first")
            return
        url = self.current_account.get('url')
        if not url:
            QMessageBox.information(self, "Info", "No URL saved for this account")
            return
        webbrowser.open(url)
        self.reset_autolock()

    # ---------- dialogs ----------
    def add_dialog(self):
        dlg = AddAccountDialog(self)
        if dlg.exec():
            acct = dlg.account
            for a in self._data.get('accounts', []):
                if a.get('shortcut','').lower() == acct.shortcut.lower():
                    QMessageBox.warning(self, "Error", "Shortcut already exists")
                    return
            self._data.setdefault('accounts', []).append(asdict(acct))
            self.write_encrypted()
            self.render_list()
            QMessageBox.information(self, "Saved", "Account saved to vault")
            self.reset_autolock()

    # ---------- events ----------
    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress):
            if self._key:
                self.reset_autolock()
        return super().eventFilter(obj, event)


# ---------- dialogs ----------
class AddAccountDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add account")
        self.account: Optional[Account] = None
        layout = QFormLayout(self)
        self.shortcut = QLineEdit()
        self.service = QLineEdit()
        self.url = QLineEdit()
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.tags = QLineEdit()
        self.notes = QTextEdit()
        layout.addRow("Shortcut:", self.shortcut)
        layout.addRow("Service:", self.service)
        layout.addRow("URL:", self.url)
        layout.addRow("Username:", self.username)
        layout.addRow("Password:", self.password)
        layout.addRow("Tags:", self.tags)
        layout.addRow("Notes:", self.notes)
        btns = QHBoxLayout()
        save = QPushButton("Save")
        save.clicked.connect(self.do_save)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        btns.addWidget(save); btns.addWidget(cancel)
        layout.addRow(btns)

    def do_save(self):
        sh = self.shortcut.text().strip()
        svc = self.service.text().strip()
        user = self.username.text().strip()
        pw = self.password.text().strip()
        if not sh or not svc or not user:
            QMessageBox.warning(self, "Missing", "Shortcut, service and username are required")
            return
        tags = [t.strip() for t in self.tags.text().split(',') if t.strip()]
        self.account = Account(shortcut=sh, service=svc, url=self.url.text().strip(),
                               username=user, password=pw, notes=self.notes.toPlainText(), tags=tags)
        self.accept()


class CreateVaultDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Vault")
        layout = QFormLayout(self)
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Master password:", self.pw)
        layout.addRow("Confirm password:", self.pw2)
        btns = QHBoxLayout()
        create = QPushButton("Create")
        create.clicked.connect(self.do_create)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        btns.addWidget(create); btns.addWidget(cancel)
        layout.addRow(btns)
        self.password = None

    def do_create(self):
        p1 = self.pw.text().strip()
        p2 = self.pw2.text().strip()
        if not p1 or p1 != p2:
            QMessageBox.warning(self, "Error", "Passwords must match and not be empty")
            return
        self.password = p1
        self.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = VaultApp()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
