import angr
import os, sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--backward", '-b', type=int, help="choose BackwardSlice", required=True)
args = parser.parse_args()

pyfile = sys.argv[0]
cwd = os.path.dirname(pyfile)

normalization = True
print("normalization is {}".format(normalization))
fileNm = "priBetween"
path = os.path.join(cwd, fileNm)
if normalization:
    fileNm += "_withNorm"
else:
    fileNm += "_withoutNorm"

b = angr.Project(path, load_options={"auto_load_libs": False})

# get fn Obj from fn name
cfgDecom = b.analyses.CFGFast(data_references=True, normalize=True)

fnNm = 'checkPrimeNumber'
fnNm = 'main'
# func = cfgBS.kb.functions.function(name=fnNm)
func = cfgDecom.kb.functions.function(name=fnNm)

# to do backward slicing on fn level
cfgBS = b.analyses.CFGEmulated(keep_state=True, \
                          state_add_options=angr.sim_options.refs, \
                          starts = [func.addr], \
                          normalize = normalization, \
                          call_depth = 0, \
                          context_sensitivity_level=0)
cdg = b.analyses.CDG(cfgBS, start = func.addr)
ddg = b.analyses.DDG(cfgBS, start = func.addr)
tarAddr = int(0x40121c) # int(0x401226) # int(0x401189) # prim
# tarAddr = target_func.addr # test
# tarAddr = int(0x40116b) # int(0x401175) # testB
target_node = cfgBS.model.get_any_node(tarAddr)
index = 9 # 10 # 5 # pri
# index =  75 # test
# index =  29 # 9 # testB
bs = b.analyses.BackwardSlice(cfgBS, cdg=cdg, ddg=ddg, targets=[ (target_node, index) ])
print({hex(x[0]):x[1] for x in bs.chosen_statements.items()})
# target_node.block.vex.pp()
# print(bs.dbg_repr(None))

# to check two node sets from CFGFast and CFGEmulated
# nodes from CFGEmulated should be a subset of nodes from CFGFast
# because CFGFast refers to the whole bianry but CFGEmulated refers to a fn.
nodesBS = cfgBS.graph.nodes()
nodesBSInfo = [(hex(n.addr), n.size) for n in nodesBS]
nodesDecom = cfgDecom.graph.nodes()
nodesDecomInfo = [(hex(n.addr), n.size) for n in nodesDecom]
if len(nodesBS) > 0 and len(nodesDecom) > 0:
    sub = [e for e in nodesBSInfo if e in nodesDecomInfo]
    print(sub)
    if len(sub) == len(nodesBSInfo):
        print("CFG for BS is a subset of CFG for decompliation")
    else:
        print("CFG for BS is NOT a subset of CFG for decompliation")
else:
    print("nodesBS or nodesDecom wrong")

# cfgDecom = b.analyses.CFGFast(data_references=True, normalize=True)

if not args.backward:
    # dec = b.analyses.Decompiler(func, cfg=cfgDecom.model)
    dec = b.analyses.Decompiler(func, cfg=cfgBS.model)
    print("on whole fn")
else:
    # dec = b.analyses.Decompiler((func,bs.chosen_statements), cfg=cfgDecom.model)
    dec = b.analyses.Decompiler((func,bs.chosen_statements), cfg=cfgBS.model)
    print("on backward")

# print(type(d))
code = dec.codegen.text
print(code)

import angr
from angrutils import *
import networkx as nx
import pygraphviz as gv
import matplotlib.pyplot as plt
import subprocess

pngdir = os.path.join(cwd, 'png')
print(pngdir)
if not os.path.exists(pngdir):
  subprocess.run(['mkdir', '-p', pngdir])
fileNm = os.path.basename(fileNm)
fileNm = os.path.join(pngdir, fileNm)

plot_cfg(cfgBS, fileNm+"_cfg", asminst=True, remove_imports=True, remove_path_terminator=True, format="raw") 
plot_cdg(cfgBS, cdg, fileNm+"_cdg") 
plot_dfg(ddg.graph, fileNm+"_ddg") 
process = subprocess.run(['dot', '-Tpng', '-o', fileNm+"_cfg.png", fileNm+"_cfg.raw"])
