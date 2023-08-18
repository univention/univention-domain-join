#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2017-2023 Univention GmbH
# SPDX-License-Identifier: AGPL-3.0-only

import importlib
import logging
import os
import subprocess
import sys
from logging import getLogger
from typing import Dict, Optional, Tuple

from PyQt5.QtCore import QRegExp, QThread, pyqtSignal
from PyQt5.QtGui import QFontMetrics, QIcon, QPixmap, QRegExpValidator
from PyQt5.QtWidgets import QAction, QApplication, QBoxLayout, QCheckBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenuBar, QMessageBox, QPushButton, QVBoxLayout, QWidget

from univention_domain_join.distributions import AbstractJoiner
from univention_domain_join.utils.distributions import get_distribution
from univention_domain_join.utils.domain import get_master_ip_through_dns, get_ucs_domainname
from univention_domain_join.utils.general import execute_as_root, ssh

LOG = '/var/log/univention/domain-join-gui.log'


def check_if_run_as_root() -> None:
	if os.getuid() != 0:
		app = QApplication(sys.argv)
		form = NotRootDialog()
		form.show()
		sys.exit(app.exec_())


@execute_as_root
def set_up_logging(logfile: str) -> None:
	verbose_formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
	plain_formatter = logging.Formatter('%(message)s')

	os.makedirs(os.path.dirname(logfile), exist_ok=True)
	logfile_handler = logging.FileHandler(logfile)
	logfile_handler.setLevel(logging.DEBUG)
	logfile_handler.setFormatter(verbose_formatter)

	stdout_handler = logging.StreamHandler(sys.stdout)
	stdout_handler.setLevel(logging.DEBUG)
	stdout_handler.setFormatter(plain_formatter)

	userinfo_logger = logging.getLogger('userinfo')
	userinfo_logger.setLevel(logging.DEBUG)
	userinfo_logger.addHandler(logfile_handler)
	userinfo_logger.addHandler(stdout_handler)


class DomainJoinException(Exception):
	pass


class SshException(Exception):
	pass


class DistributionException(Exception):
	pass


class NotRootDialog(QMessageBox):
	def __init__(self) -> None:
		super().__init__()
		self.setWindowTitle('Univention Domain Join')
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		self.setWindowIcon(QIcon(scriptDir + os.path.sep + 'univention_icon.svg'))
		self.setText('This tool must be executed as root.')


class DomainJoinGui(QMainWindow):

	def __init__(self) -> None:
		super().__init__()

		self.regex_ipv4 = r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}'
		self.regex_ipv6 = r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
		self.regex_domainname = r'(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,8}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})'

		self.setWindowTitle("Univention Domain Join")
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		self.setWindowIcon(QIcon(scriptDir + os.path.sep + 'univention_icon.svg'))

		self.build_main_window()

		# Make the join_button the focused element on startup.
		self.setTabOrder(self.join_button, self.cancel_button)
		self.setTabOrder(self.cancel_button, self.domainname_or_ip_input)
		self.setTabOrder(self.domainname_or_ip_input, self. admin_username_input)
		self.setTabOrder(self.admin_username_input, self.admin_password_input)

	def build_main_window(self) -> None:
		main_layout = QVBoxLayout()

		self.add_menu_bar()
		self.add_general_description_group(main_layout)
		self.add_hline(main_layout)
		self.add_inputs_group(main_layout)
		main_layout.addStretch(1)
		self.add_buttons(main_layout)
		self.admin_password_input.returnPressed.connect(self.join_button.click)

		central_widget = QWidget()
		central_widget.setLayout(main_layout)
		self.setCentralWidget(central_widget)

	def add_menu_bar(self) -> None:
		menu_bar = QMenuBar(self)

		help_menu = menu_bar.addMenu('Help')
		about_action = QAction('About', self)
		about_action.triggered.connect(self.about)
		help_menu.addAction(about_action)

		self.setMenuBar(menu_bar)

	def about(self) -> None:
		self.about_dialog = QMessageBox.about(
			self, 'About',
			'<h1>Univention Domain Join</h1>'
			'<p>Univention Domain Join is a tool, which helps you integrate an '
			'Ubuntu computer into an Univention Corporate Server domain.</p>'
			'If you need help visit the <a href="https://help.univention.com/">Univention '
			'forum</a> or <a href="https://www.univention.com/contact/">contact us</a>.'
			'<p>Copyright: <a href="https://www.univention.com">Univention GmbH</a></p>'
		)

	def add_general_description_group(self, layout: QBoxLayout) -> None:
		description_group = QWidget()
		description_group_layout = QHBoxLayout()
		self.add_general_description(description_group_layout)
		description_group_layout.addStretch(1)
		self.add_domain_join_icon(description_group_layout)
		description_group.setLayout(description_group_layout)
		layout.addWidget(description_group)

	def add_general_description(self, layout: QBoxLayout) -> None:
		short_description = QLabel(
			'<h3>Univention Domain Join Assistant</h3>'
			'<p>Use this tool to configure this computer to be part of your UCS domain.</p>'
		)
		font_metrics = QFontMetrics(short_description.font())
		short_description.setMinimumWidth(40 * font_metrics.width('a'))
		short_description.setWordWrap(True)
		layout.addWidget(short_description, stretch=10)

	def add_domain_join_icon(self, layout: QBoxLayout) -> None:
		icon = QLabel()
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		icon.setPixmap(QPixmap(scriptDir + os.path.sep + 'domain.png'))
		layout.addWidget(icon)

	def add_hline(self, layout: QBoxLayout) -> None:
		frame = QFrame()
		frame.setFrameShape(QFrame.HLine)
		layout.addWidget(frame)

	def add_inputs_group(self, layout: QBoxLayout) -> None:
		inputs_box = QWidget()
		inputs_box_layout = QVBoxLayout()
		self.add_inputs_description(inputs_box_layout)
		self.add_domainname_or_ip_input(inputs_box_layout)
		self.add_username_input(inputs_box_layout)
		self.add_password_input(inputs_box_layout)
		self.add_force_ucs_dns(inputs_box_layout)
		inputs_box.setLayout(inputs_box_layout)
		layout.addWidget(inputs_box)

	def add_inputs_description(self, layout: QBoxLayout) -> None:
		inputs_description = QLabel(
			'To perform the domain join you need to provide the domain name or '
			'the IP address of an UCS DC and the credentials of a domain administrator.'
		)
		inputs_description.setWordWrap(True)
		layout.addWidget(inputs_description)

	def add_domainname_or_ip_input(self, layout: QBoxLayout) -> None:
		short_description = QLabel('Domain name or IP address:')
		short_description.setWordWrap(True)
		layout.addWidget(short_description)
		self.domainname_or_ip_input = QLineEdit()
		font_metrics = QFontMetrics(self.domainname_or_ip_input.font())
		self.domainname_or_ip_input.setFixedWidth(32 * font_metrics.width('a'))
		self.domainname_or_ip_input.setPlaceholderText('e.g. mydomain.com or 10.0.0.4')
		domainname_or_ip_validator = QRegExpValidator(QRegExp(
			r'%s|%s|%s' % (self.regex_ipv4, self.regex_ipv6, self.regex_domainname)
		), self)
		self.domainname_or_ip_input.setValidator(domainname_or_ip_validator)
		layout.addWidget(self.domainname_or_ip_input)
		self.try_filling_in_domainname()

	def try_filling_in_domainname(self) -> None:
		self.domainname_thread = DomainnameDetectionThread()
		self.domainname_or_ip_input.setPlaceholderText('Detecting domain name...')
		self.domainname_thread.domain['QString'].connect(self.domainname_detection_successful)
		self.domainname_thread.finished.connect(self.domainname_detection_finished)
		self.domainname_thread.start()

	def domainname_detection_successful(self, domainname: str) -> None:
		domainname_qregex = QRegExp(self.regex_domainname)
		# self.domainname_or_ip_input.text() is used to make sure the user
		# didn't fill in the field already.
		if not self.domainname_or_ip_input.text() and domainname_qregex.exactMatch(domainname):
			self.domainname_or_ip_input.setText(domainname)
			self.admin_password_input.setFocus()

	def domainname_detection_finished(self) -> None:
		self.domainname_or_ip_input.setPlaceholderText('e.g. mydomain.com or 10.0.0.4')

	def add_username_input(self, layout: QBoxLayout) -> None:
		short_description = QLabel('Domain administrator\'s username:')
		short_description.setWordWrap(True)
		layout.addWidget(short_description)
		self.admin_username_input = QLineEdit()
		font_metrics = QFontMetrics(self.domainname_or_ip_input.font())
		self.admin_username_input.setFixedWidth(32 * font_metrics.width('a'))
		self.admin_username_input.setPlaceholderText('Username')
		self.admin_username_input.setText('Administrator')
		username_validator = QRegExpValidator(QRegExp(r'\w+'), self)
		self.admin_username_input.setValidator(username_validator)
		layout.addWidget(self.admin_username_input)

	def add_force_ucs_dns(self, layout: QBoxLayout) -> None:
		short_description = QLabel('Change the system\'s DNS settings and set the UCS DC as DNS nameserver (default is to use the standard network settings, but make sure the your system can resolve the hostname of the UCS DC and the UCS master system)')
		short_description.setWordWrap(True)
		layout.addWidget(short_description)
		self.force_ucs_dns_input = QCheckBox('Set UCS DC as DNS server')
		layout.addWidget(self.force_ucs_dns_input)

	def add_password_input(self, layout: QBoxLayout) -> None:
		short_description = QLabel('Domain administrator\'s password:')
		short_description.setWordWrap(True)
		layout.addWidget(short_description)

		self.admin_password_input = QLineEdit()
		font_metrics = QFontMetrics(self.domainname_or_ip_input.font())
		self.admin_password_input.setFixedWidth(32 * font_metrics.width('a'))
		self.admin_password_input.setPlaceholderText('Password')
		self.admin_password_input.setEchoMode(QLineEdit.Password)
		password_validator = QRegExpValidator(QRegExp(r'.+'), self)
		self.admin_password_input.setValidator(password_validator)
		layout.addWidget(self.admin_password_input)

	def add_buttons(self, layout: QBoxLayout) -> None:
		button_widget = QWidget()
		button_layout = QHBoxLayout()
		button_layout.addStretch()
		self.join_button = QPushButton('Join')
		self.join_button.clicked.connect(self.join_domain_if_inputs_are_ok)
		self.join_button.setAutoDefault(True)
		button_layout.addWidget(self.join_button)
		self.cancel_button = QPushButton('Cancel')
		self.cancel_button.clicked.connect(exit)
		button_layout.addWidget(self.cancel_button)
		button_widget.setLayout(button_layout)
		layout.addWidget(button_widget)

	def join_domain_if_inputs_are_ok(self) -> None:
		if (
			self.domainname_or_ip_input.hasAcceptableInput() and
			self.admin_username_input.hasAcceptableInput() and
			self.admin_password_input.hasAcceptableInput()
		):
			dc_ip, domain = self.get_domainname_or_dc_ip()
			if not dc_ip and domain:
				dc_ip = get_master_ip_through_dns(domain)
			if not dc_ip:
				DnsNotWorkingDialog().exec_()
				return
			self.join_domain(dc_ip, str(self.admin_username_input.text()), str(self.admin_password_input.text()), self.force_ucs_dns_input.isChecked())
		else:
			MissingInputsDialog().exec_()

	def get_domainname_or_dc_ip(self) -> Tuple[Optional[str], Optional[str]]:
		input_text = self.domainname_or_ip_input.text()
		domainname_qregex = QRegExp(self.regex_domainname)
		ip_qregex = QRegExp('%s|%s' % (self.regex_ipv4, self.regex_ipv6))
		if domainname_qregex.exactMatch(input_text):
			return None, input_text
		elif ip_qregex.exactMatch(input_text):
			return input_text, None
		else:
			return None, None

	def join_domain(self, dc_ip: str, admin_username: str, admin_pw: str, force_ucs_dns: bool) -> None:
		self.join_thread = JoinThread(dc_ip, admin_username, admin_pw, force_ucs_dns)
		self.join_thread.join_started.connect(self.join_started)
		self.join_thread.join_successful.connect(self.join_successful)
		self.join_thread.join_failed['QString'].connect(self.join_failed)
		self.join_thread.ssh_failed.connect(self.ssh_failed)
		self.join_thread.dist_failed.connect(self.dist_failed)
		self.join_thread.start()

	def join_started(self) -> None:
		self.join_button.setText('Joining...')
		self.join_button.setEnabled(False)
		self.cancel_button.setEnabled(False)

	def join_successful(self) -> None:
		self.join_button.setText('Join')
		self.cancel_button.setText('Close')
		self.cancel_button.setEnabled(True)
		SuccessfulJoinDialog().exec_()

	def join_failed(self, err: str) -> None:
		self.join_button.setText('Join')
		self.join_button.setEnabled(True)
		self.cancel_button.setEnabled(True)
		FailedJoinDialog(err).exec_()

	def ssh_failed(self) -> None:
		self.join_button.setText('Join')
		self.join_button.setEnabled(True)
		self.cancel_button.setEnabled(True)
		FailedSSHDialog().exec_()

	def dist_failed(self) -> None:
		self.join_button.setText('Join')
		self.join_button.setEnabled(False)
		self.cancel_button.setEnabled(True)
		FailedDistDialog().exec_()


class SuccessfulJoinDialog(QMessageBox):
	def __init__(self) -> None:
		super().__init__()
		self.setWindowTitle('Successful Join')
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		self.setWindowIcon(QIcon(scriptDir + os.path.sep + 'univention_icon.svg'))
		self.setText('The domain join was successful. Please reboot the system.')


class FailedJoinDialog(QMessageBox):
	def __init__(self, err: str) -> None:
		super().__init__()
		self.setWindowTitle('Failed Join')
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		self.setWindowIcon(QIcon(scriptDir + os.path.sep + 'univention_icon.svg'))
		self.setStyleSheet("QMessageBox { messagebox-text-interaction-flags: 5; }")
		self.setText(
			'The domain join failed: {} For further information look at {}'.format(err, LOG)
		)


class FailedSSHDialog(QMessageBox):
	def __init__(self) -> None:
		super().__init__()
		self.setWindowTitle('SSH Connection Failed')
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		self.setWindowIcon(QIcon(scriptDir + os.path.sep + 'univention_icon.svg'))
		self.setText(
			'The SSH connection failed. Please check the address/username/password.'
		)


class FailedDistDialog(QMessageBox):
	def __init__(self) -> None:
		super().__init__()
		self.setWindowTitle('Distribution Check Failed')
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		self.setWindowIcon(QIcon(scriptDir + os.path.sep + 'univention_icon.svg'))
		self.setText(
			'The used distribution {} is not supported.'.format(get_distribution())
		)


class MissingInputsDialog(QMessageBox):
	def __init__(self) -> None:
		super().__init__()
		self.setWindowTitle('Missing Inputs')
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		self.setWindowIcon(QIcon(scriptDir + os.path.sep + 'univention_icon.svg'))
		self.setText(
			'At least one input field is not filled in, or filled with an invalid input.'
			' Please fill all three input fields according to their description.'
		)


class DnsNotWorkingDialog(QMessageBox):
	def __init__(self) -> None:
		super().__init__()
		self.setWindowTitle('DNS Not Working')
		scriptDir = os.path.dirname(os.path.realpath(__file__))
		self.setWindowIcon(QIcon(scriptDir + os.path.sep + 'univention_icon.svg'))
		self.setText(
			'No DNS record for the DC master could be found. Please make sure '
			'that the DC master is the DNS server for this computer or use this'
			' tool with the IP address of the DC master.'
		)


class DomainnameDetectionThread(QThread):
	domain = pyqtSignal('QString')

	def run(self) -> None:
		domainname = get_ucs_domainname()
		if domainname:
			self.domain.emit(domainname)


class JoinThread(QThread):
	join_started = pyqtSignal()
	ssh_failed = pyqtSignal()
	dist_failed = pyqtSignal()
	join_failed = pyqtSignal('QString')
	join_successful = pyqtSignal()

	def __init__(self, dc_ip: str, admin_username: str, admin_pw: str, force_ucs_dns: bool) -> None:
		super().__init__()
		self.dc_ip = dc_ip
		self.admin_username = admin_username
		self.admin_pw = admin_pw
		self.force_ucs_dns = force_ucs_dns

	def run(self) -> None:
		self.join_started.emit()
		try:
			try:
				distribution_joiner = self.get_joiner_for_this_distribution()
			except SshException:
				self.ssh_failed.emit()
				return
			except DistributionException:
				self.dist_failed.emit()
				return
			distribution_joiner.check_if_join_is_possible_without_problems()
			distribution_joiner.create_backup_of_config_files()
			distribution_joiner.join_domain()
		except Exception as e:
			getLogger("userinfo").critical(e, exc_info=True)
			self.join_failed.emit(str(e))
			return
		self.join_successful.emit()

	def get_joiner_for_this_distribution(self) -> AbstractJoiner:
		distribution = get_distribution()
		try:
			distribution_join_module = importlib.import_module('univention_domain_join.distributions.%s' % (distribution.lower(),))
			self.check_if_ssh_works_with_given_account()
			ucr_variables = self.get_ucr_variables_from_dc()
			if not ucr_variables:
				raise DomainJoinException()
			return distribution_join_module.Joiner(ucr_variables, self.admin_username, self.admin_pw, self.dc_ip, False, self.force_ucs_dns)
		except ImportError:
			getLogger("userinfo").critical('The used distribution "%s" is not supported.' % (distribution,))
			raise DistributionException()

	def check_if_ssh_works_with_given_account(self) -> bool:
		cmd = "true"
		ssh_process = ssh(self.admin_username, self.admin_pw, self.dc_ip, cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
		_, stderr = ssh_process.communicate()
		logging.getLogger('debugging').debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
		if ssh_process.returncode != 0:
			if stderr.decode().strip().endswith(': No route to host'):
				raise SshException('IP not reachable via SSH.')
			else:
				raise SshException('It\'s not possible to connect to the UCS DC via ssh, with the given credentials.')
			return False
		return True

	def get_ucr_variables_from_dc(self) -> Optional[Dict[str, str]]:
		cmd = "/usr/sbin/ucr shell"
		ssh_process = ssh(self.admin_username, self.admin_pw, self.dc_ip, cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		assert ssh_process.stdout
		ucr_variables = dict(
			line.decode("utf-8", "replace").strip().split("=", 1)
			for line in ssh_process.stdout
		)

		_, stderr = ssh_process.communicate()
		logging.getLogger('debugging').debug("%r returned %d: %s", cmd, ssh_process.returncode, stderr.decode())
		if ssh_process.wait() != 0:
			getLogger("userinfo").critical('Fetching the UCR variables from the UCS DC failed.')
			return None

		ucr_variables.pop("hostname", None)
		return ucr_variables


if __name__ == '__main__':
	check_if_run_as_root()
	ruid = int(os.environ.get('PKEXEC_UID', 0)) or int(os.environ.get('SUDO_UID', 0))
	if ruid:
		os.setresuid(ruid, ruid, 0)

	set_up_logging(LOG)
	app = QApplication.setSetuidAllowed(True)
	app = QApplication(sys.argv)
	form = DomainJoinGui()
	form.show()
	sys.exit(app.exec_())
