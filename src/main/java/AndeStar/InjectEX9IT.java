package AndeStar;

import java.lang.reflect.Array;
import java.math.BigInteger;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;

class MyDisassembler {
	Program program = null;
	private ProgramContext programContext = null;
	private Language language = null;
	private Memory memory = null;
	private int pointerSize;
	static final int MAX_REPEAT_BYTES_LIMIT = 4;
	private int maxInstructions = 4000;
	private boolean respectExecuteFlag = false;
	private int lastCheckValidDisassemblyCount;

	public MyDisassembler(Program program) {
		this.program = program;
		this.memory = program.getMemory();
		this.language = program.getLanguage();
		this.pointerSize = program.getDefaultPointerSize();
		this.programContext = program.getProgramContext();
	}

	public PseudoInstruction disassemble(Address disasmAddr, Address fetchAddr, byte bytes[])
			throws InsufficientBytesException, UnknownInstructionException,
			UnknownContextException {

		PseudoDisassemblerContext procContext = new PseudoDisassemblerContext(programContext);
		return disassemble(disasmAddr, fetchAddr, bytes, procContext);
	}

	public PseudoInstruction disassemble(Address disasmAddr, Address fetchAddr, byte bytes[],
			PseudoDisassemblerContext disassemblerContext) throws InsufficientBytesException,
			UnknownInstructionException, UnknownContextException {

		Address zero = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);

		MemBuffer memBuffer = new ByteMemBufferImpl(disasmAddr, bytes, language.isBigEndian());

		// check that address is defined in memory
		try {
			memBuffer.getByte(0);
		}
		catch (Exception e) {
			return null;
		}

		InstructionPrototype prototype = null;
		disassemblerContext.flowStart(disasmAddr);
		prototype = language.parse(memBuffer, disassemblerContext, false);

		if (prototype == null) {
			return null;
		}

		PseudoInstruction instr;
		try {
			// first, normal decode
			instr = new PseudoInstruction(program, disasmAddr, prototype, memBuffer, disassemblerContext);
			// if it's branch, it's decoded as if current pc is 0
			// Must avoid passing program to PseudoInstruction, otherwise it will read from program at the given addr - which we're trying to avoid
			FlowType flowType = prototype.getFlowType(instr);
			if (flowType.isCall() || flowType.isJump()) {
				instr = new PseudoInstruction(program.getAddressFactory(), zero, prototype, memBuffer, disassemblerContext);
			}
		}
		catch (AddressOverflowException e) {
			throw new InsufficientBytesException(
				"failed to build pseudo instruction at " + disasmAddr + ": " + e.getMessage());
		}

		return instr;
	}
}

public class InjectEX9IT extends InjectPayloadCallother {
	private int INSTRUCTION_TABLE_ENTRY_LENGTH = 4;
	private AddressSpace defaultSpace;
	private CodeUnitFormat codeUnitFormat;
	private Register itbReg;

	public InjectEX9IT(String sourceName, SleighLanguage language) {
		super(sourceName);
		itbReg = language.getRegister("ITB");
		defaultSpace = language.getAddressFactory().getDefaultAddressSpace();
		codeUnitFormat = new CodeUnitFormat(new CodeUnitFormatOptions());
	}

	PseudoInstruction disasmAt(Program program, Address disasmAddr, Address fetchAddr) {
		MyDisassembler disassembler = new MyDisassembler(program);
		byte[] data = new byte[INSTRUCTION_TABLE_ENTRY_LENGTH];
		try {
			if (program.getMemory().getBytes(fetchAddr, data) != Array.getLength(data)) {
				return null;
			}
			return disassembler.disassemble(disasmAddr, fetchAddr, data);
		} catch (Exception ex) {
			return null;
		}
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		Address ex9itAddr = con.baseAddr;
		int imm9u = (int) con.inputlist.get(0).getOffset();
		int itOffset = imm9u * INSTRUCTION_TABLE_ENTRY_LENGTH;

		BigInteger ITB = program.getProgramContext().getValue(itbReg, ex9itAddr, false);
		if (ITB == null) {
			return null;
		}
		long memOffset = (ITB.longValue() & ~0b11) + itOffset;

		Address fetchAddr = defaultSpace.getAddress(memOffset);
		if (fetchAddr.getOffset() == 0) {
			return null;
		}
		// HACK: disasm at addr 0 to make J/JAL work. Might make other things using
		// inst_start incorrect.
		// XXX this is STILL broken. disasm comment will be wrong, but pcode will be
		// correct.
		// I guess there's some caching behavior somewhere that fucks up the comment
		// generated by getRepresentationString.
		PseudoInstruction insn = disasmAt(program, ex9itAddr, fetchAddr);
		// Could be bad ITB
		if (insn == null) {
			return null;
		}

		String mnem = insn.getMnemonicString();
		if (mnem != null) {
			if (mnem.equals("EX9.IT")) {
				// hw would generate Reserved Instruction Exception
				return null;
			}

			// 32bit insns which use inst_next (PC + 4) need to be fixed up to use PC + 2,
			// since EX9.IT is 16bit.
			// if J : PC = concat(PC[31,25], (Inst[23,0] << 1)) // not signed?
			// if JAL : R30 = PC + 2; PC = concat(PC[31,25], (Inst[23,0] << 1))
			// JRAL, JRAL.xTON, JRALNEZ, BGEZAL, BLTZAL: RT = PC + 2

			// Set comment if there's a valid insn referenced.
			Listing listing = program.getListing();
			/*
			if (listing.getComment(CodeUnit.EOL_COMMENT, ex9itAddr) == null) {
				// getRepresentationString is slow and requires insn to have associated program
				if (insn.getProgram() != null) {
					String ex9itComment = codeUnitFormat.getRepresentationString(insn);
					program.withTransaction("set EX9.IT comment", () -> {
						listing.setComment(ex9itAddr, CodeUnit.EOL_COMMENT, String.format("%s {%s}", fetchAddr.toString(), ex9itComment));
					});
				} else {
					program.withTransaction("set EX9.IT comment", () -> {
						listing.setComment(ex9itAddr, CodeUnit.EOL_COMMENT, fetchAddr.toString());
					});
				}
			}
			*/

			// works, but also extremely slow. guess it should be done in analysis
			CodeUnit cu = listing.getCodeUnitAt(ex9itAddr);
			if (Array.getLength(cu.getMnemonicReferences()) == 0) {
				program.withTransaction("set EX9.IT refs", () -> {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.removeAllReferencesFrom(ex9itAddr);
					Reference[] refs = insn.getReferencesFrom();
					for (Reference ref : refs) {
						cu.addMnemonicReference(ref.getToAddress(), ref.getReferenceType(), ref.getSource());
					}
				});
			}
		}

		// NOTE SymbolicPropogator must be patched to allow STORE pcode ops
		return insn.getPcode();
	}

}
