// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"cmp"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// A Block is a contiguous sequence of instructions that are executed together.
// Boundaries are defined by branching instructions.
//
// Blocks are attached to instructions via metadata and should not be modified
// after being created.
//
// It should never contain direct references to the original asm.Instructions
// since copying the ProgramSpec won't update pointers to the new copied insns.
// This is a problem when modifying instructions through
// [Blocks.LiveInstructions] after reachability analysis, since it would modify
// the original ProgramSpec's instructions.
type Block struct {
	id         uint64
	raw        asm.RawInstructionOffset
	start, end int

	// If this block is the start of a function, sym is set to the function name.
	sym string

	predecessors []*Block
	branch       *Block
	fthrough     *Block

	// calls are blocks that are called from this block.
	calls *[]*Block
}

func (b *Block) first(insns asm.Instructions) *asm.Instruction {
	if len(insns) == 0 {
		return nil
	}

	if b.start >= len(insns) {
		return nil
	}

	return &insns[b.start]
}

func (b *Block) last(insns asm.Instructions) *asm.Instruction {
	if len(insns) == 0 {
		return nil
	}

	if b.end >= len(insns) {
		return nil
	}

	return &insns[b.end]
}

func (b *Block) iterate(insns asm.Instructions) *Iterator {
	if b.start < 0 || b.end < 0 || b.start >= len(insns) || b.end >= len(insns) {
		return nil
	}

	return &Iterator{
		block:   b,
		insns:   insns,
		insnIdx: b.start,
		offset:  b.raw,
	}
}

// backtrack returns a Backtracker starting at the end of the block.
//
// After the next call to [Backtracker.Previous], the backtracker will point to
// the last instruction in the block.
func (b *Block) backtrack(insns asm.Instructions) *Backtracker {
	return newBacktracker(b, insns)
}

// Func returns the BTF function metadata associated with the block, if any. If
// the block is not the start of a function, it returns nil.
func (b *Block) Func(insns asm.Instructions) *btf.Func {
	if b.sym == "" {
		return nil
	}

	first := b.first(insns)
	if first == nil {
		return nil
	}

	return btf.FuncMetadata(first)
}

func (b *Block) String() string {
	return b.Dump(nil)
}

func (b *Block) Dump(insns asm.Instructions) string {
	var sb strings.Builder

	if b.sym != "" {
		sb.WriteString(fmt.Sprintf("Function: %s\n", b.sym))
	}

	sb.WriteString("Predecessors: [")
	for i, from := range b.predecessors {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("%d", from.id))
	}
	sb.WriteString("]\n")
	sb.WriteString(fmt.Sprintf("Start: %d (raw %d), end: %d\n", b.start, b.raw, b.end))
	sb.WriteString("\n")

	if len(insns) != 0 {
		sb.WriteString("Instructions:\n")
		i := b.iterate(insns)
		for i.NextInstruction() {
			ins := i.Instruction()
			if ins.Symbol() != "" {
				fmt.Fprintf(&sb, "\t%s:\n", ins.Symbol())
			}
			if src := ins.Source(); src != nil {
				line := strings.TrimSpace(src.String())
				if line != "" {
					fmt.Fprintf(&sb, "\t%*s; %s\n", 4, " ", line)
				}
			}
			fmt.Fprintf(&sb, "\t%*d: %v\n", 4, i.RawInstructionOffset(), ins)
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("Instructions: not provided, call Dump() with insns\n")
	}

	if b.calls != nil && len(*b.calls) > 0 {
		sb.WriteString("Calls: [")
		for i, callee := range *b.calls {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%d", callee.id))
		}
		sb.WriteString("]\n")
	}

	if b.branch != nil {
		sb.WriteString("Branch: ")
		sb.WriteString(fmt.Sprintf("%d", b.branch.id))
		sb.WriteString("\n")
	}

	if b.fthrough != nil {
		sb.WriteString("Fallthrough: ")
		sb.WriteString(fmt.Sprintf("%d", b.fthrough.id))
		sb.WriteString("\n")
	}

	return sb.String()
}

// Iterator is a linear (meaning ignoring control flow) forward iterator over
// one or more blocks and the instructions represented by those blocks.
type Iterator struct {
	// blockIdx is the position of block within blocks. blocks may be a window
	// of a larger block list, so this doesn't always equal block.id.
	blockIdx int
	block    *Block
	blocks   Blocks

	// insnIdx is the index of ins within insns.
	insnIdx int
	ins     *asm.Instruction
	insns   asm.Instructions
	offset  asm.RawInstructionOffset
}

// Instruction returns the current instruction pointed to by the Iterator.
func (i *Iterator) Instruction() *asm.Instruction {
	return i.ins
}

// InstructionIndex returns the index of the current instruction within the
// iterated Blocks.
func (i *Iterator) InstructionIndex() int {
	return i.insnIdx
}

// RawInstructionOffset returns the raw instruction offset of the instruction
// within the program.
func (i *Iterator) RawInstructionOffset() asm.RawInstructionOffset {
	return i.offset
}

// NextBlock pulls the next block in the iterator's block list, if it exists.
// Otherwise, returns false.
//
// Positions the iterator at the start of the next block. Offset is updated to
// the raw offset of the first instruction in the next block.
func (i *Iterator) NextBlock() bool {
	if i.block == nil {
		return false
	}

	if i.blockIdx+1 >= len(i.blocks) {
		return false
	}

	i.blockIdx++
	i.block = i.blocks[i.blockIdx]
	i.insnIdx = i.block.start
	i.offset = i.block.raw
	i.ins = &i.insns[i.insnIdx]

	return true
}

// NextInstruction advances the iterator to the next instruction in the block. If the end
// of the block is reached, it will either stop (if iterating locally) or roll
// over to the next block (if iterating globally).
func (i *Iterator) NextInstruction() bool {
	if i.block == nil || i.insnIdx < i.block.start || i.insnIdx > i.block.end {
		return false
	}

	// On the first call, pull the first insn and return.
	if i.ins == nil {
		i.ins = &i.insns[i.insnIdx]
		return true
	}

	if i.insnIdx+1 > i.block.end {
		// Roll over to the next block if iterating globally and there is a next
		// block. False if iterating locally or there's no next block.
		return i.NextBlock()
	}

	i.insnIdx++
	i.offset += asm.RawInstructionOffset(i.ins.Size() / asm.InstructionSize)
	i.ins = &i.insns[i.insnIdx]

	return true
}

// Backtrack returns a Backtracker starting at the current instruction of the
// BlockIterator.
//
// The first call to [Backtracker.Instruction] will return the same instruction
// as the current instruction of the BlockIterator.
//
// [Backtracker.Previous] will return the instruction preceding the current one,
// if any.
func (i *Iterator) Backtrack() *Backtracker {
	return newBacktracker(i.block, i.insns).Seek(i.insnIdx)
}

// Backtracker is an iterator that walks backwards through a Block's
// instructions.
//
// This is useful for finding the last instruction that wrote to a register
// before it is read, by following the control flow backwards.
type Backtracker struct {
	insns asm.Instructions

	block   *Block
	visited []*Block

	index int
	ins   *asm.Instruction
}

// newBacktracker creates a new Backtracker starting at the end of the given
// block.
func newBacktracker(block *Block, insns asm.Instructions) *Backtracker {
	bt := &Backtracker{
		insns: insns,
		block: block,
		index: block.end,
	}

	return bt
}

// Instruction returns the current instruction.
func (bt *Backtracker) Instruction() *asm.Instruction {
	return bt.ins
}

// Previous moves to the previous instruction within the block.
// Returns false when reaching the start of the block.
func (bt *Backtracker) Previous() bool {
	// First call to Previous, point to the current instruction.
	if bt.ins == nil {
		bt.ins = &bt.insns[bt.index]
		return true
	}

	// Make sure index doesn't underrun the start of the block.
	prev := bt.index - 1
	if prev < bt.block.start {
		// Roll over to the Block's only predecessor, if any.
		return bt.previousBlock()
	}

	// Update index and ins in lockstep to avoid subtle bugs.
	bt.index = prev
	bt.ins = &bt.insns[prev]

	return true
}

// Seek moves the Backtracker to the given instruction index within the block
// and pulls the instruction.
//
// Panics if the index is out of bounds of the block.
func (bt *Backtracker) Seek(index int) *Backtracker {
	if index < bt.block.start || index > bt.block.end {
		panic(fmt.Sprintf("seek index %d out of bounds for block [%d, %d]", index, bt.block.start, bt.block.end))
	}

	bt.index = index
	bt.ins = &bt.insns[index]

	return bt
}

// previousBlock rolls over the Backtracker to the first and only predecessor of
// the current block, if any. Returns false if there is no predecessor or if
// there are multiple predecessors.
func (bt *Backtracker) previousBlock() bool {
	if len(bt.block.predecessors) != 1 {
		return false
	}

	pred := bt.block.predecessors[0]

	// Prevent infinite loops when backtracking.
	//
	// In the vast majority of cases, backtracking terminates in the first
	// predecessor, either because of a positive match, the register got
	// clobbered, or because of multiple grandparents.
	//
	// Maintaining a visited list tends to dominate the CPU and memory profiles of
	// the backtracking process, so avoid it whenever possible.
	if pred == bt.block {
		// Never roll over to self.
		return false
	}
	if len(bt.visited) == 0 {
		// First rollover, initialize visited list in a single allocation.
		bt.visited = []*Block{bt.block, pred}
	} else {
		// Subsequent rollovers, check visited list and append if needed.
		if slices.Contains(bt.visited, pred) {
			return false
		}
		bt.visited = append(bt.visited, pred)
	}

	bt.block = pred
	bt.index = pred.end
	bt.ins = &bt.insns[pred.end]

	return true
}

// Clone creates a copy of the Backtracker at its current position.
func (bt *Backtracker) Clone() *Backtracker {
	cpy := *bt
	cpy.visited = slices.Clone(cpy.visited)

	return &cpy
}

// Blocks is a list of basic blocks.
type Blocks []*Block

func (bl Blocks) count() uint64 {
	return uint64(len(bl))
}

func (bl Blocks) first() *Block {
	if len(bl) == 0 {
		return nil
	}
	return bl[0]
}

func (bl Blocks) iterate(insns asm.Instructions) *Iterator {
	if len(bl) == 0 {
		return nil
	}

	i := bl.first().iterate(insns)
	if i == nil {
		return nil
	}
	i.blocks = bl

	return i
}

// Name returns the symbol name of the first block, e.g. the function name if
// the Blocks make up the start of a function.
func (bl Blocks) Name() string {
	if len(bl) == 0 {
		return ""
	}
	return bl.first().sym
}

// Func returns the BTF function metadata associated with the first block, if
// any.
func (bl Blocks) Func(insns asm.Instructions) *btf.Func {
	if len(bl) == 0 {
		return nil
	}
	return bl.first().Func(insns)
}

// Instructions yields pointers to the blocks' instructions in order, keyed by
// an index relative to the first block's first instruction. For a function's
// Blocks, index 0 is the entry instruction, carrying its symbol and BTF
// metadata.
func (bl Blocks) Instructions(insns asm.Instructions) iter.Seq2[int, *asm.Instruction] {
	return func(yield func(int, *asm.Instruction) bool) {
		iter := bl.iterate(insns)
		if iter == nil {
			return
		}

		i := 0
		for iter.NextInstruction() {
			if !yield(i, iter.Instruction()) {
				return
			}
			i++
		}
	}
}

// funcs yields the functions in the block list as subslices. The first block
// starts the first function, subsequent functions start at blocks carrying BTF
// func metadata. Blocks with a symbol but no BTF func metadata (e.g. jump
// labels) don't start a new function.
func (bl Blocks) funcs(insns asm.Instructions) iter.Seq[Blocks] {
	return func(yield func(Blocks) bool) {
		iter := bl.iterate(insns)
		if iter == nil {
			return
		}

		start := 0
		for iter.NextBlock() {
			if iter.block.Func(insns) == nil {
				continue
			}
			if !yield(bl[start:iter.blockIdx]) {
				return
			}
			start = iter.blockIdx
		}
		yield(bl[start:])
	}
}

func (bl Blocks) String() string {
	return bl.Dump(nil)
}

func (bl Blocks) Dump(insns asm.Instructions) string {
	var sb strings.Builder
	for _, block := range bl {
		sb.WriteString(fmt.Sprintf("\n=== Block %d ===\n", block.id))
		sb.WriteString(block.Dump(insns))
		sb.WriteString("\n")
	}
	return sb.String()
}

// MakeBlocks returns a list of basic blocks of instructions that are always
// executed together. Multiple calls on the same insns will return the same
// Blocks object.
//
// Blocks are created by finding branches and jump targets in the given insns
// and cutting up the instruction stream accordingly.
func MakeBlocks(insns asm.Instructions) (Blocks, error) {
	if len(insns) == 0 {
		return nil, errors.New("insns is empty, cannot compute blocks")
	}

	if blocks := loadBlocks(insns); blocks != nil {
		return blocks, nil
	}

	blocks, err := computeBlocks(insns)
	if err != nil {
		return nil, fmt.Errorf("computing blocks: %w", err)
	}

	if err := storeBlocks(insns, blocks); err != nil {
		return nil, fmt.Errorf("storing blocks: %w", err)
	}

	return blocks, nil
}

// computeBlocks computes the basic blocks from the given instruction stream.
func computeBlocks(insns asm.Instructions) (Blocks, error) {
	n := len(insns)
	if n == 0 {
		return nil, errors.New("insns is empty, cannot compute blocks")
	}

	// Step 1: Precompute raw instruction offsets.
	rawOffsets := make([]asm.RawInstructionOffset, n)
	var offset asm.RawInstructionOffset
	for i := range insns {
		rawOffsets[i] = offset
		offset += asm.RawInstructionOffset(insns[i].Size() / asm.InstructionSize)
	}

	// Step 2: Identify block starts (leaders).
	isLeader := make([]bool, n)
	isLeader[0] = true

	var hasFuncRef bool
	for i := range insns {
		ins := &insns[i]
		if ins.Symbol() != "" {
			isLeader[i] = true
		}

		if ins.IsFunctionReference() {
			hasFuncRef = true
		}

		op := ins.OpCode
		jump := op.JumpOp()
		switch jump {
		case asm.InvalidJumpOp, asm.Call:
			// No branch, regular instruction.
			continue

		case asm.Exit:
			// Exit ends the block. The next instruction, if any, starts a new block.
			if i+1 < n {
				isLeader[i+1] = true
			}

		default:
			// Jump instruction (Ja or conditional jump). It ends the current block.
			if i+1 < n {
				isLeader[i+1] = true
			}

			raw, err := jumpTarget(rawOffsets[i], ins)
			if err != nil {
				return nil, fmt.Errorf("determine jump target instruction offset: %w", err)
			}

			if tgtIdx, found := slices.BinarySearch(rawOffsets, raw); found {
				isLeader[tgtIdx] = true
			}
		}
	}

	// Step 3: Count and allocate blocks.
	numBlocks := 0
	for _, l := range isLeader {
		if l {
			numBlocks++
		}
	}
	if numBlocks == 0 {
		return nil, errors.New("no blocks created, this is a bug")
	}

	arena := make([]Block, numBlocks)
	blocks := make(Blocks, numBlocks)
	k := 0
	for i := range insns {
		if !isLeader[i] {
			continue
		}
		if k > 0 {
			blocks[k-1].end = i - 1
		}
		arena[k] = Block{
			id:    uint64(k),
			raw:   rawOffsets[i],
			start: i,
			sym:   insns[i].Symbol(),
		}
		blocks[k] = &arena[k]
		k++
	}
	blocks[numBlocks-1].end = n - 1

	if start := blocks.first().start; start != 0 {
		return nil, fmt.Errorf("first block starts at instruction index %d; this could be a bug, or the first insn is not a symbol", start)
	}

	// Step 4: Wire branch and fallthrough targets.
	for _, blk := range blocks {
		lastIns := &insns[blk.end]
		op := lastIns.OpCode
		jump := op.JumpOp()

		if jump != asm.InvalidJumpOp && jump != asm.Call && jump != asm.Exit {
			raw, err := jumpTarget(rawOffsets[blk.end], lastIns)
			if err != nil {
				return nil, fmt.Errorf("determine jump target instruction offset: %w", err)
			}

			if targetBlockIdx, found := slices.BinarySearchFunc(blocks, raw, func(b *Block, r asm.RawInstructionOffset) int {
				return cmp.Compare(b.raw, r)
			}); found {
				blk.branch = blocks[targetBlockIdx]
			}
		}

		if canFallthrough(lastIns) && blk.id+1 < uint64(len(blocks)) {
			blk.fthrough = blocks[blk.id+1]
		}
	}

	// Step 5: Wire predecessors directly.
	for _, blk := range blocks {
		if blk.branch != nil {
			if !slices.Contains(blk.branch.predecessors, blk) {
				blk.branch.predecessors = append(blk.branch.predecessors, blk)
			}
		}
		if blk.fthrough != nil && blk.fthrough != blk.branch {
			if !slices.Contains(blk.fthrough.predecessors, blk) {
				blk.fthrough.predecessors = append(blk.fthrough.predecessors, blk)
			}
		}
	}

	// Step 6: Connect calls lazily.
	if hasFuncRef {
		funcs := make(map[string]*Block)
		for _, blk := range blocks {
			if blk.sym != "" {
				funcs[blk.sym] = blk
			}
		}

		for _, blk := range blocks {
			var calls []*Block
			for idx := blk.start; idx <= blk.end; idx++ {
				ins := &insns[idx]
				if !ins.IsFunctionReference() {
					continue
				}
				sym := ins.Reference()
				if sym == "" {
					continue
				}
				if target, ok := funcs[sym]; ok {
					calls = append(calls, target)
				}
			}
			if len(calls) > 0 {
				calls := calls
				blk.calls = &calls
			}
		}
	}

	return blocks, nil
}

// blocksKey is used to store Blocks in an instruction's metadata.
type blocksKey struct{}

// storeBlocks associates the given Blocks with the first instruction in the
// given insns.
//
// If insns is empty, does nothing.
func storeBlocks(insns asm.Instructions, bl Blocks) error {
	if len(insns) == 0 {
		return errors.New("insns is empty, cannot store Blocks")
	}

	insns[0].Metadata.Set(blocksKey{}, bl)

	return nil
}

// loadBlocks retrieves the Blocks associated with the first instruction in the
// given insns.
//
// If no Blocks is present, returns nil.
func loadBlocks(insns asm.Instructions) Blocks {
	if len(insns) == 0 {
		return nil
	}

	blocks, ok := insns[0].Metadata.Get(blocksKey{}).(Blocks)
	if !ok {
		return nil
	}

	return blocks
}
