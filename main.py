import sys
import random
from os import getenv
from redis import Redis, StrictRedis
from bcrypt import hashpw, gensalt, checkpw
from PySide2 import QtWidgets, QtCore
from PySide2.QtCore import Slot, Qt, QObject
import jwt
import requests


class LoginUI(QtWidgets.QMainWindow):
    def __init__(self):
        super(LoginUI, self).__init__()

        self.login = False
        self.user_name = ''
        self.password = ''
        self.button = []
        self.user_name_label = QtWidgets.QLabel("user name: ")
        self.user_name_le = QtWidgets.QLineEdit()
        self.user_name_le.setPlaceholderText("Enter you username")

        self.password_label = QtWidgets.QLabel("Password: ")
        self.password_le = QtWidgets.QLineEdit()
        self.password_le.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_le.setPlaceholderText("set your password")
        self.login_button = QtWidgets.QPushButton("&login", self)
        self.login_button.setDisabled(False)
        self.login_button.clicked.connect(self.courier_list_window)
        self.login_button.setMaximumSize(50, 50)

        self.layout = QtWidgets.QFormLayout()
        self.layout.addWidget(self.user_name_label)
        self.layout.addWidget(self.user_name_le)
        self.jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_le)
        self.layout.addWidget(self.login_button)

        widget = QtWidgets.QWidget()
        widget.setLayout(self.layout)
        self.setCentralWidget(widget)
        self.setWindowTitle("Aplikacja zarządzania paczkami")
        self.resize(600, 240)

    @Slot()
    def magic(self):
        self.text.setText(random.choice(self.hello))

    def status_package(self, i):


        link = 'https://pawelosinskiprzesylkiprojekt.herokuapp.com' + str(self.button[i])
        encoded_jwt = jwt.encode({'username': 'courier'}, self.jwt_token, algorithm='HS256')
        _jwt = str(encoded_jwt).split("'")
        jwt_ = _jwt[1]
        headers = {"Authorization": "Bearer " + jwt_}

        r = requests.put(link, headers = headers)
        print(self.button[i] + r.text)
        self.courier_list_window()
        text = 'Wszystkie przesyłki'

    def verify_user(self, username, password):
        salt = gensalt(5)
        password = password.encode()
        REDIS_HOST = 'ec2-3-121-188-229.eu-central-1.compute.amazonaws.com'
        REDIS_PASS = 'V&2asU5aDYCFuuvacpSodx8DFjdj$'
        db = StrictRedis(REDIS_HOST, db=23, password=REDIS_PASS)
        hashed = db.hget(f"courier:{username}", "password")
        if not hashed:
            print(f"Wrong password or username!")
            return False

        return checkpw(password, hashed)

    def courier_list_window(self):
        if not self.login:
            login_text = self.user_name_le.text()
            pass_text = self.password_le.text()
            if not login_text or not pass_text:
                dialog = QtWidgets.QMessageBox()
                dialog.setText("wrong login or password")
                dialog.setStyleSheet("color: red")
                self.layout.addWidget(dialog)
                return 0

            if self.verify_user(login_text, pass_text):
                self.login = True


        if self.login:
            self.button = []
            self.resize(400, 400)
            layout2 = QtWidgets.QFormLayout()
            i = 0
            encoded_jwt = jwt.encode({'username': 'courier'}, self.jwt_token, algorithm='HS256')
            _jwt = str(encoded_jwt).split("'")
            jwt_ = _jwt[1]
            headers = {"Authorization": "Bearer " + jwt_}
            r = requests.get('https://pawelosinskiprzesylkiprojekt.herokuapp.com/labels', headers=headers)
            if r.status_code != 200:
                dialog = QtWidgets.QMessageBox()
                dialog.setText("You dont have permission to log on")
                dialog.setStyleSheet("color: red")
                self.layout.addWidget(dialog)
                return 0
            text = 'Wszystkie przesyłki'
            qlabel_title = QtWidgets.QLabel(text)
            qlabel_title.setStyleSheet("font: 18pt;font-weight: 700")
            layout2.addWidget(qlabel_title)
            jsonik = r.json()
            for table in jsonik['_embedded']['items']:
                status = ""
                text_for_button = ""
                przycisk = False
                link = table['_links']['set_status']['href']
                if table['status'] == 1:
                    status = "zlecone"
                    text_for_button = "przejmij przesyłke"
                    przycisk = True
                if table['status'] == 2:
                    status = "w trakcie realizacji"
                    text_for_button = "potwierdz doręczenie przesyłki"
                    przycisk = True
                if table['status'] == 3:
                    status = "doręczone"

                self.status_button = QtWidgets.QPushButton(text_for_button, self)

                button_text = table['_links']['set_status']['href']
                self.button.append(button_text)
                self.status_button.clicked.connect(lambda checked=True, x=i: self.status_package(x))

                self.status_button.setDisabled(False)
                i = i + 1

                text = 'uid: ' + table['uid'] + ' |  from who: ' + table['username'] + ' | size ' + table[
                    'size'] + ' | address: ' + table['address'] + ' | id post office: ' + table[
                           'id_post_office'] + ' | create data: ' + table['date'] + ' | status: ' + status
                qlabel_for_one_label = QtWidgets.QLabel(text)
                layout2.addWidget(qlabel_for_one_label)
                if przycisk:
                    layout2.addWidget(self.status_button)

            self.setWindowTitle("Aplikacja kuriera")

            # table = QtWidgets.QTableWidget(i, 5)

            #  layout2.addWidget(table)
            widget = QtWidgets.QWidget()
            widget.setLayout(layout2)
            self.setCentralWidget(widget)
        else:
            dialog = QtWidgets.QMessageBox()
            dialog.setText("wrong login or password")
            dialog.setStyleSheet("color: red")
            self.layout.addWidget(dialog)



if __name__ == "__main__":
    app = QtWidgets.QApplication()
    login_page = LoginUI()
    login_page.show()

    sys.exit(app.exec_())
