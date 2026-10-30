import subprocess,sys
from pathlib import Path
import shutil
kernel,out=map(Path,sys.argv[1:3])
def key(s):return s.replace("-","_")
all_modules={}
for p in kernel.rglob("*.ko"):
 name=subprocess.check_output(["modinfo","-F","name",str(p)],text=True).strip()
 all_modules[key(name)]=p
order=[];seen=set()
def visit(name):
 name=key(name)
 if name in seen:return
 seen.add(name)
 if name not in all_modules:raise SystemExit("Missing required module "+name)
 p=all_modules[name]
 deps=subprocess.check_output(["modinfo","-F","depends",str(p)],text=True).strip()
 for d in filter(None,deps.split(",")):visit(d)
 shutil.copyfile(p,out/p.name)
 print(name,subprocess.check_output(["modinfo","-F","vermagic",str(p)],text=True).strip())
 order.append(p.name)
visit("wireguard")
(out/"load-order").write_text("\n".join(order)+"\n")
