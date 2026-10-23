"""Xaxglog runner — secure generic OSINT tool executor.

Picked from: aenoshrajora/OSINTel-Dashboard (app.py + data.json)
Upgrades vs upstream:
  - no shell=True anywhere (shlex list exec)
  - {{placeholder}} substitution with shlex.quote + unresolved check
  - path-traversal guards on output read/download
  - atomic JSON writes, capped history (500)
  - SSE streaming endpoint re-uses same saver
"""
import datetime
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import threading
import uuid
import logging

logger = logging.getLogger(__name__)

_SAFE_ID_RE = re.compile(r'^[\w\-.]{1,128}$')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "default_tools.json")
# Fallback: legacy copy location
if not os.path.exists(DATA_FILE):
    alt = os.path.join(BASE_DIR, "..", "..", "data", "runner_tools.json")
    DATA_FILE = alt


def is_safe_id(v: str) -> bool:
    return bool(_SAFE_ID_RE.match(v or ""))


def sanitize_filename(v: str, max_len: int = 40) -> str:
    return re.sub(r'[^\w.\-]', '_', str(v))[:max_len]


def build_cmd_list(cmd: str | list) -> list:
    if isinstance(cmd, list):
        return cmd
    try:
        return shlex.split(cmd)
    except ValueError as e:
        raise ValueError(f"Invalid command: {e}")


def run_command(cmd, timeout=300, cwd=None):
    if isinstance(cmd, str):
        cmd = build_cmd_list(cmd)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                cwd=cwd, errors="replace")
        out, err = proc.communicate(timeout=timeout)
        return out, err, proc.returncode == 0
    except subprocess.TimeoutExpired:
        proc.kill(); proc.communicate()
        return "", f"Timeout after {timeout}s", False
    except FileNotFoundError:
        return "", f"Not found: {cmd[0]}", False
    except Exception as e:
        return "", str(e), False


def run_streaming(cmd, timeout=300, cwd=None):
    if isinstance(cmd, str):
        cmd = build_cmd_list(cmd)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                cwd=cwd, errors="replace")
        q: queue.Queue = queue.Queue()
        done = threading.Event()

        def reader():
            try:
                for line in proc.stdout:
                    q.put(line)
            finally:
                done.set()
        threading.Thread(target=reader, daemon=True).start()
        deadline = datetime.datetime.utcnow() + datetime.timedelta(seconds=timeout)
        while not done.is_set() or not q.empty():
            if datetime.datetime.utcnow() > deadline:
                proc.kill()
                yield "[ERROR] timed out\n"
                return
            try:
                yield q.get(timeout=0.1)
            except queue.Empty:
                continue
        proc.wait()
        yield "\n[DONE]\n" if proc.returncode == 0 else f"\n[EXIT {proc.returncode}]\n"
    except FileNotFoundError:
        yield f"[ERROR] not found: {cmd[0]}\n"
    except Exception as e:
        yield f"[ERROR] {e}\n"


def substitute(template: str, rep: dict) -> str:
    out = template
    for k, v in rep.items():
        out = out.replace("{{" + k + "}}", shlex.quote(str(v)))
    leftover = re.findall(r'\{\{[\w_]+\}\}', out)
    if leftover:
        raise ValueError(f"Unresolved: {', '.join(leftover)}")
    return out


def load_tools(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_tools(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def resolve_output(pattern, tool, inputs, ts):
    name = pattern or "{{TOOL_ID}}_{{TIMESTAMP}}.txt"
    name = name.replace("{{TOOL_ID}}", tool.get("id", "tool"))
    name = name.replace("{{TIMESTAMP}}", ts)
    name = name.replace("{{UUID}}", uuid.uuid4().hex[:8])
    safe_tool = sanitize_filename(tool.get("name", "tool").lower())
    name = name.replace("{{TOOL_NAME_SANITIZED}}", safe_tool)
    for fld in tool.get("input_fields", []):
        fid = fld["id"]
        val = sanitize_filename(str(inputs.get(fid, "")))
        name = name.replace("{{INPUT__" + fid + "}}", val)
        name = name.replace("{{" + fid + "}}", val)
    return re.sub(r'[^\w.\-]', '_', name) or f"output_{ts}.txt"
