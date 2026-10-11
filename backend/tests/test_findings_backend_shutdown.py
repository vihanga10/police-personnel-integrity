"""Actual committed pipe transport; child doubles exercise denial and hard stop."""
import ast
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

import pytest

ROOT=Path(__file__).resolve().parents[2]


def exchange():
    source=ast.parse((ROOT/'backend/app/identity/findings_backend_service.py').read_text())
    nodes=[n for n in source.body if isinstance(n,ast.FunctionDef) and n.name in ('_json','_exchange')]
    def require(value,message):
        if not value:raise ValueError(message)
    scope=dict(json=json,os=os,selectors=selectors,subprocess=subprocess,time=time,
        require=require,LIMIT=1048576,encoded=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode())
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<committed transport>','exec'),scope)
    return scope['_exchange']


def child(tmp_path,body):
    script=tmp_path/'worker.py';script.write_text('import json,sys,time\njson.loads(sys.stdin.readline())\n'+body)
    return [sys.executable,str(script)]


def request():return "print(json.dumps(dict(kind='guard',id=1,action='BEFORE_SUBMIT',selection={},mode='EXECUTE')),flush=True)\n"

def deny(*args):raise ValueError('Source denied')


def test_ordered_denial_allows_owned_cleanup_preserves_original_failure(tmp_path):
    marker=tmp_path/'cleaned'
    command=child(tmp_path,request()+
        "reply=json.loads(sys.stdin.readline())\nassert reply==dict(kind='denied',id=1)\n"+
        f"open({str(marker)!r},'w').write('unwound')\nsys.exit(1)\n")
    with pytest.raises(ValueError,match='Source denied'):exchange()(command,{},deny,timeout=5)
    assert marker.read_text()=='unwound'


def test_nonresponsive_denied_worker_remains_bounded_without_retry(tmp_path):
    marker=tmp_path/'runs'
    command=child(tmp_path,f"open({str(marker)!r},'a').write('1')\n"+request()+
        "assert json.loads(sys.stdin.readline())['kind']=='denied'\ntime.sleep(30)\n")
    started=time.monotonic()
    with pytest.raises(ValueError,match='Source denied'):exchange()(command,{},deny,timeout=1)
    assert time.monotonic()-started<6 and marker.read_text()=='1'


def test_actual_crash_preserves_owned_lock_no_automatic_clear(tmp_path):
    lock=tmp_path/'stale-lock'
    command=child(tmp_path,f"import os\nos.mkdir({str(lock)!r})\nsys.exit(7)\n")
    with pytest.raises(ValueError):exchange()(command,{},deny,timeout=3)
    assert lock.is_dir()
