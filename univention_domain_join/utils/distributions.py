import subprocess


def get_distribution():
	return subprocess.check_output(['lsb_release', '-is']).strip()
