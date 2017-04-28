from __future__ import print_function
from binaryninja import *

# TODO: rule out impossible nestings to speed up traversing

def traverse_llil_basic_block(f_type, f, block):
    for instr in block:
        #assert type(instr) == LowLevelILInstruction
        traverse_typed(f_type, f, LowLevelILInstruction, instr)


def traverse_function(f_type, f, funk):
    for bb in funk.low_level_il.basic_blocks:
        traverse_typed(f_type, f, LowLevelILBasicBlock, bb)
    for bb in funk.basic_blocks:
        traverse_typed(f_type, f, BasicBlock, bb)


def traverse_binary_view(f_type, f, bv):
    for funk in bv.functions:
        traverse_typed(f_type, f, Function, funk)


def traverse_dummy(f_type, f, node):
    return


traversers = {
    BasicBlock: traverse_dummy,
    BinaryView: traverse_binary_view,
    Function: traverse_function,
    LowLevelILBasicBlock: traverse_llil_basic_block,
}


def traverse_typed(f_type, f, node_type, node):
    if issubclass(f_type, node_type):
        #print("Applying", f_type, node_type)
        return f(node)
    else:
        if node_type in traversers:
            traversers[node_type](f_type, f, node)
        else:
            print('fyb> missing traverser for "{}"'.format(node_type))


def typify(f_type):
    def dec(f):
        def inner(node):
            node_type = type(node)
            return traverse_typed(f_type, f, node_type, node)
        return inner
    return dec


import gen_syscall_table
import json
syscall_table = json.load(open(gen_syscall_table.syscall_path, 'r'))


@typify(Function)
def syscall_traverse_functions(f):
    # Need this wrapper since I can't seem to find a way to get a reference to Function from a LLIL instruction
    syscalls = []

    @typify(LowLevelILInstruction)
    def syscall_comment(node):
        if not node.operation == LowLevelILOperation.LLIL_SYSCALL:
            return

        rax = node.get_reg_value('rax')
        if rax.type == RegisterValueType.ConstantValue:
            rax = rax.value
            key = str(rax)
            name = syscall_table[key] if key in syscall_table else 'unk({:02X})'.format(rax)
            f.set_comment(node.address, name)
            print('fyb> found syscall @ 0x{:08X}: {}'.format(node.address, name))
            syscalls.append(name)
        else:
            print('fyb> unknown syscall @ 0x{:08X} => {}'.format(node.address, rax))
    syscall_comment(f)

    if len(syscalls) == 1 and f.name.startswith('sub_'):
        f.name = '_calls_{}'.format(syscalls[0])


@typify(Function)
def print_calls(funk):
    print('fyb> {}'.format(funk.name))

    @typify(LowLevelILInstruction)
    def print_call(instr):
        if not instr.operation == LowLevelILOperation.LLIL_CALL:
            return

        print('\t{}'.format(instr))

    print_call(funk)
