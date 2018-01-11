#! /usr/bin/env python

import os
from PyQt4.QtCore import QThread
from PyQt4.QtCore import pyqtSlot
from PyQt4.QtCore import SIGNAL
from PyQt4.QtCore import QRegExp
from PyQt4.QtGui import QApplication
from PyQt4.QtGui import QHBoxLayout
from PyQt4.QtGui import QLabel
from PyQt4.QtGui import QLineEdit
from PyQt4.QtGui import QRegExpValidator
from PyQt4.QtGui import QPushButton
from PyQt4.QtGui import QVBoxLayout
from PyQt4.QtGui import QWidget
from PyQt4.QtGui import QMessageBox
import sys
import logging


def check_if_run_as_root():
	if os.getuid() != 0:
		app = QApplication(sys.argv)
		form = NotRootDialog()
		form.show()
		sys.exit(app.exec_())


def set_up_logging():
	verbose_formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
	plain_formatter = logging.Formatter('%(message)s')

	if not os.path.exists('/var/log/univention/'):
		os.makedirs('/var/log/univention/')
	logfile_handler = logging.FileHandler('/var/log/univention/domain-join-gui.log')
	logfile_handler.setLevel(logging.DEBUG)
	logfile_handler.setFormatter(verbose_formatter)

	stdout_handler = logging.StreamHandler(sys.stdout)
	stdout_handler.setLevel(logging.DEBUG)
	stdout_handler.setFormatter(plain_formatter)

	userinfo_logger = logging.getLogger('userinfo')
	userinfo_logger.setLevel(logging.DEBUG)
	userinfo_logger.addHandler(logfile_handler)
	userinfo_logger.addHandler(stdout_handler)


class NotRootDialog(QMessageBox):
	def __init__(self):
		super(self.__class__, self).__init__()
		self.setText(
			'This tool must be executed as root.'
		)


class DomainJoinGui(QWidget):
	def __init__(self):
		super(self.__class__, self).__init__()

		self.resize(320, 300)
		self.setWindowTitle("Univention Domain Join")

		self.build_main_window()

		# Make the join_button the focused element on startup.
		self.setTabOrder(self.join_button, self.cancel_button)
		self.setTabOrder(self.cancel_button, self.domainname_or_ip_input)
		self.setTabOrder(self.domainname_or_ip_input, self. admin_username_input)
		self.setTabOrder(self.admin_username_input, self.admin_password_input)

	def build_main_window(self):
		# TODO: First check if join is possible.

		main_layout = QVBoxLayout()

		self.add_general_description(main_layout)
		self.add_domainname_or_ip_input(main_layout)
		self.add_username_input(main_layout)
		self.add_password_input(main_layout)
		main_layout.addStretch()
		self.add_buttons(main_layout)

		self.setLayout(main_layout)

	def add_general_description(self, main_layout):
		short_description = QLabel(
			'Fill in all input fields and press "Join" to integrate this system'
			' into your UCS domain.'
		)
		short_description.setWordWrap(True)
		main_layout.addWidget(short_description)

	def add_domainname_or_ip_input(self, main_layout):
		# TODO: pre-fill with domain name if it can be figured out

		short_description = QLabel('UCS domain name or IP address of DC master:')
		short_description.setWordWrap(True)
		main_layout.addWidget(short_description)

		self.domainname_or_ip_input = QLineEdit()
		self.domainname_or_ip_input.setPlaceholderText('e.g. mydomain.intranet or 192.168.0.14')
		domainname_or_ip_validator = QRegExpValidator(QRegExp(
			r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}|'  # IPv4
			r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|'  # IPv6
			r'(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})'  # Domain name
		), self)
		self.domainname_or_ip_input.setValidator(domainname_or_ip_validator)
		main_layout.addWidget(self.domainname_or_ip_input)

	def add_username_input(self, main_layout):
		short_description = QLabel('Username of a domain administrator:')
		short_description.setWordWrap(True)
		main_layout.addWidget(short_description)

		self.admin_username_input = QLineEdit()
		self.admin_username_input.setPlaceholderText('e.g. Administrator')
		username_validator = QRegExpValidator(QRegExp(r'\w+'), self)
		self.admin_username_input.setValidator(username_validator)
		main_layout.addWidget(self.admin_username_input)

	def add_password_input(self, main_layout):
		short_description = QLabel('Password of the domain administrator:')
		short_description.setWordWrap(True)
		main_layout.addWidget(short_description)

		self.admin_password_input = QLineEdit()
		self.admin_password_input.setEchoMode(QLineEdit.Password)
		password_validator = QRegExpValidator(QRegExp(r'.+'), self)
		self.admin_password_input.setValidator(password_validator)
		main_layout.addWidget(self.admin_password_input)

	def add_buttons(self, main_layout):
		button_widget = QWidget()
		button_layout = QHBoxLayout()

		button_layout.addStretch()

		self.join_button = QPushButton('Join')
		self.join_button.clicked.connect(self.join_domain_if_inputs_are_ok)
		button_layout.addWidget(self.join_button)

		self.cancel_button = QPushButton('Cancel')
		self.cancel_button.clicked.connect(exit)
		button_layout.addWidget(self.cancel_button)

		button_widget.setLayout(button_layout)
		main_layout.addWidget(button_widget)

	@pyqtSlot()
	def join_domain_if_inputs_are_ok(self):
		if (
			self.domainname_or_ip_input.hasAcceptableInput() and
			self.admin_username_input.hasAcceptableInput() and
			self.admin_password_input.hasAcceptableInput()
		):
			self.join_domain()
		else:
			self.missing_inputs_dialog = MissingInputsDialog()
			self.missing_inputs_dialog.exec_()

	@pyqtSlot()
	def join_domain(self):
		self.thread = JoinThread()
		self.thread.start()

		self.connect(self.thread, SIGNAL('started()'), self.join_started)
		self.connect(self.thread, SIGNAL('join_successful()'), self.join_successful)
		self.connect(self.thread, SIGNAL('join_failed()'), self.join_failed)

	@pyqtSlot()
	def join_started(self):
		self.join_button.setText('Joining...')
		self.join_button.setEnabled(False)

		self.cancel_button.setEnabled(False)

	@pyqtSlot()
	def join_successful(self):
		self.join_button.setText('Join')
		self.cancel_button.setEnabled(True)

		self.successful_join_dialog = SuccessfulJoinDialog()
		self.connect(self.successful_join_dialog, SIGNAL('finished(int)'), exit)
		self.successful_join_dialog.exec_()

	@pyqtSlot()
	def join_failed(self):
		self.join_button.setText('Join')
		self.join_button.setEnabled(True)

		self.cancel_button.setEnabled(True)


class SuccessfulJoinDialog(QMessageBox):
	def __init__(self):
		super(self.__class__, self).__init__()
		self.setText('The domain join was successful. Please reboot the system.')


class MissingInputsDialog(QMessageBox):
	def __init__(self):
		super(self.__class__, self).__init__()
		self.setText(
			'At least on input field is not filled in, or filled with an invalid input.'
			'Please fill all three input fields according to their description.'
		)


class JoinThread(QThread):
	def __init__(
		self,
		domainname=None,
		master_ip=None,
		admin_username=None,
		admin_pw=None
	):
		super(self.__class__, self).__init__()

	def run(self):
		import time
		time.sleep(3)

		self.emit(SIGNAL('join_successful()'))
		#self.emit(SIGNAL('join_failed()'))


if __name__ == '__main__':
	# TODO: Comment in again: check_if_run_as_root()
	set_up_logging()

	app = QApplication(sys.argv)
	form = DomainJoinGui()
	form.show()
	sys.exit(app.exec_())
