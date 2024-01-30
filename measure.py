import os 
import re
import sys
import pwd
import csv
from dataclasses import dataclass
from typing import TextIO, Optional, Sequence

Pid = int
Uid = int 
STDERR = sys.stderr

# Выгружает PSS и SWAP PSS для каждого процесса в /tmp/ram.csv и выводит краткую статистику в stdout
#
# Запустите от имени root
# 
# Не забудьте отредактировать метод get_group() для фильтрации приложений


class ParseError(BaseException):
	pass

@dataclass
class ProcStat:
	pid: Pid
	ppid: Pid
	uid: int
	user: str
	cmdline: Sequence[str]
	pss_kb: int
	swap_pss_kb: int

DIGITS_RE = re.compile(r'^[0-9]+$')

def collect_ram_stat():
	all_stat = []

	with os.scandir('/proc') as it:
		for entry in it:
			if not DIGITS_RE.match(entry.name):
				continue

			stat = read_process_stat(int(entry.name), entry.path)
			if stat: 
				all_stat.append(stat)

	return all_stat


def read_process_stat(pid: Pid, proc_path: str) -> Optional[ProcStat]:
	status_file = os.path.join(proc_path, 'status')
	cmdline_file = os.path.join(proc_path, 'cmdline')
	smaps_file = os.path.join(proc_path, 'smaps_rollup')

	try:
		with open(status_file, 'rt') as f:		
			ppid, uid, name = parse_status_file(f.read(), status_file)

		with open(cmdline_file, 'rt') as f:
			cmdline = parse_cmdline(f.read())

		# Kernel threads have empty cmdline
		if cmdline == ['']:
			cmdline = [name]

		
		try:
			with open(smaps_file, 'rt') as f:
				pss_kb, swap_pss_kb = parse_smaps_rollup(f.read(), smaps_file)
		except ProcessLookupError as e:
			# Kernel threads have a smaps file but don't allow to access it
			pss_kb = 0
			swap_pss_kb = 0

	except FileNotFoundError as e:
		print(f"File not found: {e}", file=STDERR)
		return None
	# except ProcessLookupError as e:
	# 	print(f"Error reading /proc for PID {pid}: {e}")
	# 	return None
	except PermissionError as e:
		print(f"Cannot access /proc for PID {pid}: {e}. Are you root?", file=STDERR)
		return None

	return ProcStat(
		pid = pid,
		ppid = ppid,
		uid = uid,
		user = get_user_name(uid),
		cmdline = cmdline,
		pss_kb = pss_kb,
		swap_pss_kb = swap_pss_kb
	)

PPID_RE = re.compile(r'^PPid:\s*(\d+)\b', re.MULTILINE)
UIID_RE = re.compile(r'^Uid:\s*(\d+)\s+(\d+)', re.MULTILINE)
NAME_RE = re.compile(r'^Name:\s*(\S.*)$', re.MULTILINE)
def parse_status_file(content: str, path: str) -> tuple[Pid, Uid, str]:
	ppid_m = PPID_RE.search(content)
	if not ppid_m:
		raise ParseError(f"Cannot find PPid in {path}")

	uid_m = UIID_RE.search(content)
	if not uid_m:
		raise ParseError(f"Cannot find Uid in {path}")

	name_m = NAME_RE.search(content)
	if not name_m:
		raise ParseError(f"Cannot find Name in {path}")

	return int(ppid_m[1]), int(uid_m[2]), name_m[1].strip()

def parse_cmdline(cmdline: str) -> Sequence[str]:
	return cmdline.split("\0")

PSS_RE = re.compile(r'^Pss:\s*(\d+)\s*kB\b', re.MULTILINE)
SWAP_PSS_RE = re.compile(r'^SwapPss:\s*(\d+)\s*kB', re.MULTILINE)
def parse_smaps_rollup(content: str, path: str) -> tuple[int, int]:
	pss_m = PSS_RE.search(content)
	if not pss_m:
		raise ParseError(f"Cannot find Pss in {path}")

	swap_pss_m = SWAP_PSS_RE.search(content)
	if not swap_pss_m:
		raise ParseError(f"Cannot find SwapPss in {path}")

	return int(pss_m[1]), int(swap_pss_m[1])

def get_user_name(uid: Uid) -> str:
	try:
		return pwd.getpwuid(uid).pw_name
	except KeyError:
		return str(uid)

def write_to_csv(ram_stat):
	with open('/tmp/ram.csv', 'w') as f:
		writer = csv.writer(f)
		writer.writerow(['PID', 'USER', 'CMDLINE', 'PSS, Kb', 'SWAP_PSS, Kb', 'GROUP'])		

		for item in ram_stat:
			writer.writerow([
				item.pid,
				item.user,
				item.cmdline[0],
				item.pss_kb,
				item.swap_pss_kb,
				get_group(item)
			])

def count_ram(ram_stat):
	mem = {}
	total = [0, 0]

	for item in ram_stat:
		group = get_group(item)
		mem.setdefault(group, [0, 0])
		mem[group][0] += item.pss_kb
		mem[group][1] += item.swap_pss_kb
		total[0] += item.pss_kb
		total[1] += item.swap_pss_kb

	for group, (pss, swap) in mem.items():
		usage_mb = (pss + swap) / 1024
		pss_mb = pss / 1024
		swap_pss_mb = swap / 1024
		print(f"{group:20s}  {usage_mb:8.2f} Mb ({pss_mb:.2f} PSS + {swap_pss_mb:.2f} SWAP PSS)")

	print(f"{'total':20s} {total[0]/1024:.2f} Mb PSS + {total[1]/1024:.2f} Mb SWAP")


def get_group(item):
	if re.match(r'^app_', item.user):
		return item.user

	m = re.search(r'(\bfirefox\b|gnome-terminal-server|\bbash$|\bssh$)', item.cmdline[0])
	if m:
		return item.user + ':' + m[1]

	return item.user + ':*'

ram_stat = collect_ram_stat()
count_ram(ram_stat)
write_to_csv(ram_stat)