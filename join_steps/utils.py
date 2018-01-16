import os


def execute_as_root(func):
	def root_wrapper(*args, **kwargs):
		old_euid = os.geteuid()
		os.seteuid(0)
		try:
			return_value = func(*args, **kwargs)
		finally:
			os.seteuid(old_euid)
		return return_value
	return root_wrapper
