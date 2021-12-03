import angr
from angrutils import *
proj = angr.Project("../priBetween", load_options={'auto_load_libs':False})
main = proj.loader.main_object.get_symbol("checkPrimeNumber")
start_state = proj.factory.blank_state(addr=main.rebased_addr)
cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
plot_cfg(cfg, "priBetween", asminst=True, remove_imports=True, remove_path_terminator=True)  
