import angr
import os
from angrutils import *

def fnAsmPp(target_func, fnEdges, fnNodes):
    if not len(fnEdges):
        fnNodes[0].block.pp()
        return
    candidAddrs = set()
    candidAddrs.add(target_func.addr)
    seqEdges = []
    while len(fnEdges):
        nAddr = candidAddrs.pop()
        pick = [e for e in fnEdges if e[0].addr == nAddr]
        seqEdges += pick
        fnEdges = [x for x in fnEdges if x not in pick]
        nextAddr = {e[1].addr for e in pick}
        candidAddrs |= (nextAddr)

    acced = set()
    for i in range(len(seqEdges)):
        print(seqEdges[i])
        e0, e1 = seqEdges[i]
        if e0 not in acced :
            e0.block.pp()
            acced.add(e0)
        if e1 not in acced :
            e1.block.pp()
            acced.add(e1)
# import sys
# sys.path.insert(1, './angr/angr/')

# import code_location 
# Load the project
# fileNm = "testB"
fileNm = "priBetween"
path = os.path.join('../', fileNm)
b = angr.Project(path, load_options={"auto_load_libs": False})

# Generate a CFG first. In order to generate data dependence graph afterwards, you’ll have to:
# - keep all input states by specifying keep_state=True.
# - store memory, register and temporary values accesses by adding the angr.options.refs option set.
# Feel free to provide more parameters (for example, context_sensitivity_level) for CFG 
# recovery based on your needs.
cfg = b.analyses.CFGEmulated(keep_state=True, \
                          state_add_options=angr.sim_options.refs, \
                          context_sensitivity_level=0)

# idfer = b.analyses.Identifier()
# [print(hex(funInfo.addr), funInfo.name) for funInfo in idfer.func_info]
target_func1 = cfg.kb.functions.function(name='main')

fnCFG = cfg.get_function_subgraph(target_func1.addr,max_call_depth = 0)
fn1Nodes = fnCFG._graph.nodes()
fn1Edges = fnCFG._graph.edges()
# print(fnCFG._graph)
# print(fn1Nodes)
# fnAsmPp(target_func1, fn1Edges, fn1Nodes)
cfg = b.analyses.CFGEmulated(keep_state=True, \
                          state_add_options=angr.sim_options.refs, \
                          starts = [target_func1.addr], \
                          normalize = True, \
                          call_depth = 0, \
                          context_sensitivity_level=0)
# cfg.force_unroll_loops(1)
target_func1 = cfg.kb.functions.function(name='main')
# fnAsmPp(target_func1, cfg.graph.edges(), cfg.graph.nodes())
# for n in cfg.nodes_iter():
#     print(n.addr)
# x = [ type(n) for n in cfg.nodes_iter()]
# print([ (n.instruction_addrs) for n in cfg.graph.nodes])

# Generate the control dependence graph

cdg = b.analyses.CDG(cfg, start = target_func1.addr)
# print([ n.__getstate__ for n in cdg.graph.nodes])
# print(b.entry)
# print(cdg.get_dependants(b.entry))
print(cdg.graph.nodes())

# Build the data dependence graph. It might take a while. Be patient!
ddg = b.analyses.DDG(cfg, start = target_func1.addr)
# fnddg = ddg.function_dependency_graph(target_func1)
# # print(fnddg)
# blkAddr = set([n.block_addr for n in fnddg.nodes() if n.block_addr != None])
# blkAddr = set([hex(n.block_addr) for n in ddg.graph.nodes() if n.block_addr != None])
# print(blkAddr)
# blks = [cfg.model.get_any_node(n) for n in blkAddr]
# [b.block.pp() for b in blks]
# ([b.factory.block(n).pp() for n in blksAddr])
# ddgNodes = ddg.graph.nodes()
# print([hex(x.addr) for x in ddgNodes])
# cdgNodes = cdg.graph.nodes()
# print([hex(x.addr) for x in cdgNodes])
# print(cdg.graph.node_attr_dict_factory.values(2))
# cdgEdges = cdg.graph.edges
# fn = cfg.functions.values()
# x = [f for f in fn if f.name == 'main']
# for f in x:
#     blk = [b for b in f.blocks]
#     print(hex(f.addr))
# print(len(cdgNodes))
# cfgNodesAddr = [n.addr for n in cfg.graph.nodes()]
# for n in cdgNodes:
#     if n.addr in cfgNodesAddr:
#         print('hit {} size {}'.format(hex(n.addr), n.size))
#         s = cdg.get_dependants(n)
#         s=[hex(x.addr) for x in s]
#         print(s)
        # blk = b.factory.block(n.addr)
        # blk.pp()
# s = cdg.get_dependants(x[0])
# print(s)

# print(len(cdgNodes), cdgNodes)
# for x in cdgEdges:
#     print(x)
# for n in cdgNodes:
#     stmt = cdg.project.factory.block(n.addr).vex.statements
#     print(hex(n.addr))

# See where we wanna go let’s go to the exit() call, which is modeled as a 
# SimProcedure.
# target_func = cfg.kb.functions.function(name='__isoc99_scanf')
target_func = cfg.kb.functions.function(name='main')
# cfg.model.get_any_node(target_func.addr).block.pp()
# print(target_func)

# We need the CFGNode instance
tarAddr = int(0x401215) # int(0x401226) # prim
# tarAddr = target_func.addr # test
# tarAddr = int(0x40116b) # int(0x401175) # testB
target_node = cfg.model.get_any_node(tarAddr)
# [s.pp() for s in target_node.block.vex.statements]
# predecessors = cdg.get_guardians(target_node)
# print(predecessors)
# all_paths = [list(networkx.all_simple_paths(cfg.graph, pre, target_node, cutoff=3)) for pre in predecessors]
# # all_paths = [list(networkx.all_simple_paths(cfg.graph, pre, target_node)) for pre in predecessors]
# print(all_paths)
# for path in all_paths:
#     a , c = path[0][0], path[0][1]
#     print((cfg.graph[a][c].items()))
#     print(cfg.model.get_exit_stmt_idx(a, c))
#     print(hex(c.addr))
# [s.pp() for s in target_node.block.vex.statements]
# Ncfg = b.analyses.CFGEmulated(keep_state=True, \
#                           state_add_options=angr.sim_options.refs, \
#                           starts = [target_func.addr], \
#                           normalize = True, \
#                           call_depth = 0, \
#                           context_sensitivity_level=0)
# target_nodeN = Ncfg.model.get_any_node(tarAddr)
# print("#"*50)
# [s.pp() for s in target_nodeN.block.vex.statements]
# target_nodeN = Ncfg.model.get_any_node(int(0x40121c))
# print("$"*50)
# [s.pp() for s in target_nodeN.block.vex.statements]

# Let’s get a BackwardSlice out of them!
# `targets` is a list of objects, where each one is either a CodeLocation 
# object, or a tuple of CFGNode instance and a statement ID. Setting statement 
# ID to -1 means the very beginning of that CFGNode. A SimProcedure does not 
# have any statement, so you should always specify -1 for it.
# bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])
index = 12 # 10 # 5 # pri
# index =  75 # test
# index =  29 # 9 # testB
bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, index) ])
# x = [s for s in b.factory.block(target_node.addr).vex.statements]
# x[index].pp()

# ([print(hex(addr), bs.dbg_repr_run(addr)) for addr in bs.chosen_statements.keys() if addr in [n.addr for n in fn1Nodes] or addr in [n.addr for n in fn2Nodes]])
# ([print(hex(n.addr), bs.dbg_repr_run(n.addr)) for n in cfg.graph.nodes()])

# cl = code_location.CodeLocation(target_node.addr, 1100)
# print(cl in ddg)
# print(cl.__repr__())
print({hex(x[0]):x[1] for x in bs.chosen_statements.items()})
dec = b.analyses.Decompiler(target_func, cfg=cfg.model)
# dec = b.analyses.Decompiler((target_func,bs.chosen_statements), cfg=cfg.model)
code = dec.codegen.text
print(code)
# print([s.__getstate__() for s in target_node.final_states])
# print(b.factory.block(target_node.addr).pp())
# print(b.factory.block(target_node.addr).size)
# print(len([x for x in b.factory.block(target_node.addr).vex.statements]))
# bb = ([(b.factory.block(key).vex)  for key in bs.chosen_statements.keys() if key != None])
# print(bb)
# # ([x for n in bb for x in n])

# print(cfg.model.get_all_nodes(target_node.addr))
# t = bs._handle_control_dependence(target_node)
# t = t.pop()
# print(hex(t.block_addr), t.stmt_idx)
# t = ddg.get_predecessors(t)
# t= bs._handle_control_dependence(t)
# t = t.pop()
# print((t))
# Here is our awesome program slice!
# print(bs.annotated_cfg().get_last_statement_index(hex(4198809)))
# print(bs.dbg_repr())
# print(bs.chosen_statements.items())
# run_addrs = sorted(bs.chosen_statements.keys())
# s = "" # "BackwardSlice (to %s)"%target_func
# for run_addr in run_addrs:
#     s += bs.dbg_repr_run(run_addr) + "\n"
# print(s)

# print([(hex(x), bs.chosen_statements[x]) for x in bs.chosen_statements.keys()])
# print(scanStmt)
# print(cdg.graph.nodes)
# print(cdg.graph.edges)
# print('*'*30)
# print(ddg.graph.edges)
# print(len(cfg.graph.nodes))

# print(len(cdg.graph.nodes))
# print(b.loader.find_symbol('printf'))
# print(b.loader.find_symbol('__isoc99_scanf'))
# print(b.loader.find_symbol('pow'))
# print(target_node)

# print(bs.chosen_exits)
# entry_func = cfg.kb.functions[b.entry]
# print(entry_func.block_addrs)
# # print([x.addr for x in list(cfg.graph.nodes.addr)])
# print('=*'*10)
# print(cfg.graph)
# print(bs.runs_in_slice)
# # print(list(cfg.graph.edges))
# entry_node = cfg.model.get_all_nodes(b.entry)
# print([type(x) for x in entry_node])


import angr
from angrutils import *
import networkx as nx
import pygraphviz as gv
import matplotlib.pyplot as plt
import subprocess
# proj = angr.Project("../testsp", load_options={'auto_load_libs':False})

# # main = proj.loader.main_object.get_symbol("main")
# # start_state = proj.factory.blank_state(addr=main.rebased_addr)
# # cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
# print(angr.sim_options.refs)
# cfg = proj.analyses.CFGEmulated(keep_state=True, \
#                           state_add_options=angr.sim_options.refs, \
#                           context_sensitivity_level=2)
# target_func = cfg.kb.functions.function(name='main')
# fnCFG = cfg.get_function_subgraph(target_func.addr,max_call_depth = 0)
# # cdg = proj.analyses.CDG(cfg)
# # ddg = proj.analyses.DDG(cfg)
plot_cfg(cfg, fileNm+"_cfg", asminst=True, remove_imports=True, remove_path_terminator=True, format="raw") 
plot_cdg(cfg, cdg, fileNm+"_cdg") 
# # nx.drawing.nx_pydot.write_dot(ddg.graph, 'test_ddg.dot')
# gv.render('dot', 'png', 'test_ddg.dot')
plot_dfg(ddg.graph, fileNm+"_ddg") 
# A = nx.nx_agraph.to_agraph(ddg.graph)
# A.layout()
# A.draw('test_ddg.png')
process = subprocess.run(['dot', '-Tpng', '-o', fileNm+"_cfg.png", fileNm+"_cfg.raw"])
# plot_common(cdg._post_dom, fileNm+"_pdom")
# plot_common(cdg._normalized_cfg, fileNm+"ncfg")
