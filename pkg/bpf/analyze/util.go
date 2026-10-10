// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// jumpTarget calculates the target of a jump instruction based on the current
// raw instruction offset and the offset or constant present in the instruction.
// It returns the target offset and a boolean indicating whether the instruction
// is a jump instruction that causes a branch to another block.
//
// Returns false if the instruction does not branch.
func jumpTarget(raw asm.RawInstructionOffset, ins *asm.Instruction) (asm.RawInstructionOffset, error) {
	op := ins.OpCode
	class := op.Class()
	jump := op.JumpOp()

	// Only jump instructions cause a branch to another block. Execution ends at
	// an exit instruction. And calls do not cause a branch, execution continues
	// after the call.
	if !class.IsJump() || jump == asm.Exit || jump == asm.Call {
		return 0, fmt.Errorf("not a jump: %s", ins)
	}

	// Jump target is the current offset + the instruction offset + 1
	target := int64(raw) + int64(ins.Offset) + 1
	// A jump32 + JA is a 'long jump' with an offset larger than a u16. This is
	// encoded in the Constant field.
	if class == asm.Jump32Class && jump == asm.Ja {
		target = int64(raw) + ins.Constant + 1
	}

	if target < 0 {
		return 0, fmt.Errorf("jump target before start of program: %d, raw: %d, insn: %s", target, raw, ins)
	}

	return asm.RawInstructionOffset(target), nil
}

// canFallthrough checks if execution can fall through to the next instruction.
//
// An instruction can fall through if it is not a jump instruction, or if it is
// a jump instruction other than a jump-always and an exit.
func canFallthrough(ins *asm.Instruction) bool {
	if ins == nil {
		return false
	}
	if ins.OpCode.JumpOp() == asm.Ja ||
		ins.OpCode.JumpOp() == asm.Exit {
		return false
	}

	return true
}

// bpfCallers maps bpf2bpf function names to Blocks that refer to them.
type bpfCallers map[string][]*Block

// record is to be called for each instruction in a block to record function
// references found in the instructions.
//
// Blocks that contain function references get their callees populated in a
// later call to [bpfCallers.connect].
func (bc bpfCallers) record(ins *asm.Instruction, caller *Block) {
	if !ins.IsFunctionReference() {
		return
	}

	if sym := ins.Reference(); sym != "" {
		bc[sym] = append(bc[sym], caller)
	}
}

// connect populates the [Block.calls] field of all Blocks that contain function
// references with the corresponding callee Blocks.
func (bc bpfCallers) connect(blocks Blocks) {
	for _, block := range blocks {
		// Check if the block represents the start of a function.
		callee := block.sym
		if callee == "" {
			continue
		}

		// Find all callers of this function.
		callers := bc[callee]
		if callers == nil {
			continue
		}

		// Link callers to this callee block.
		for _, caller := range callers {
			if caller.calls == nil {
				caller.calls = new([]*Block)
			}
			*caller.calls = append(*caller.calls, block)
		}
	}
}
