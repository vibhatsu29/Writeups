import sys
import angr
import claripy

def main():
    with open("bytecode.bin", "rb") as f:
        bytecode_content = f.read()
    
    project = angr.Project("./vm", auto_load_libs=True)

    flag = claripy.BVS("flag", 30 * 8)

    state = project.factory.entry_state(
        args=["./vm","bytecode.bin", flag],
        add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
                    }
        )
    simfile = angr.SimFile("bytecode.bin", content=bytecode_content)
    state.fs.insert("bytecode.bin", simfile)
    for i in range(30):
        state.solver.add(flag.get_byte(i) >= 0x20,
                         flag.get_byte(i) <= 0x7e)
    simgr = project.factory.simulation_manager(state)

    simgr.explore(
        find=0x406AB6,
        avoid=0x406AE3
    )

    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(flag, cast_to=bytes)
        print(f"Flag found: {solution.decode('utf-8', errors='ignore')}")
    else:
        print("Flag not found.")
if __name__ == "__main__":
    main()