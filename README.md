# Fake Your Boilerplate

Experiments in querying Binary Ninja data structures without explicit loops.

**Note:** this is just some hacked-together Proof-of-Concept and is not meant to be anything more than that.
          Also, the 'F' in 'FYB' does not really stand for 'Fake' :)

## Description

### Problem

Traversing Binja's structures is not fun at all because one has to write loops to iterate over stuff.

### Idea

One could borrow ideas from [SYB](https://www.microsoft.com/en-us/research/wp-content/uploads/2003/01/hmap.pdf)
to provide a simple framework for querying the `BinaryView` and its children.

I don't mean to implement a SYB-style framework in python as that would be pretty pointless.
Actually, the only idea borrowed from SYB is that of exploiting a type signature to
apply functions across the nodes of a tree-like data structure.
Once again, this project is just a toy experiment of mine.

### Examples

The following is a small snippet of code to print all the `call` instructions in a `BinaryView`,
grouped by function name.
**Remember to clone (or rename) `binja-fyb/` to `fyb/` otherwise it will not work.**

```python
@typify(Function)
def print_calls(funk):
    # funk is the retrieved function
    print(funk.name)

    @typify(LowLevelILInstruction)
    def print_call(instr):
        # traverse the instructions of funk and check if we are in a CALL
        if not instr.operation == LowLevelILOperation.LLIL_CALL:
            return
        print('\t{}'.format(instr))
    
    # call the inner query
    print_call(funk)
```

In order to execute the snippet, type the following in Binja's console:

```python
import fyb; fyb.print_calls(bv)
```

If we just want to print the calls in the current function, we only need to change
the object we pass to `fyb.print_calls`:

```python
import fyb; fyb.print_calls(current_function)
```

Note that `fyb.print_calls` was not modified at all.

### Shortcomings

* Performance overhead is likely to be overkill in real scenarios,
  though it can be slightly improved by pruning the traversal
  (e.g.: there's no need to iterate over `LowLevelILOperation`s if we are searching for `Function`s)
* Binja API types are somewhat coarse
  (e.g.: flags like `LowLevelILOperation.LLIL_CALL` instead of a proper subclass of `LowLevelILOperation`)
  * I can hack around some of this stuff by using optional node filters
