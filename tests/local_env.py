"""Local harness paths only; no runtime download, build, or router access."""
import os
import pathlib
import shutil
import sys
import tempfile


def executable(variable, default):
    value = os.environ.get(variable, default)
    # Absolute paths also keep sandbox PATH wrappers from invoking themselves.
    return pathlib.Path(shutil.which(value) or value).absolute()


SCRATCH = pathlib.Path(tempfile.gettempdir())
UCODE = executable('UCODE', 'ucode')
MODULES = pathlib.Path(os.environ.get('UCODE_MODULE_DIR', '/usr/lib/ucode'))
CMD = [str(UCODE), '-L', str(MODULES)]
BUSYBOX = str(executable('BUSYBOX', 'busybox'))
JSHN = executable('JSHN', 'jshn')
JSHN_SH = pathlib.Path(os.environ.get('JSHN_SH', '/usr/share/libubox/jshn.sh'))
NFQWS2_NATIVE = executable('NFQWS2_NATIVE', 'nfqws2')
NFQWS2_GSO_NATIVE = executable('NFQWS2_GSO_NATIVE', 'nfqws2-gso')
HTTP3_CURL = executable('HTTP3_CURL', 'curl-http3')
HTTP3_PYTHON = executable('HTTP3_PYTHON', sys.executable)
