package plugin.core.analysis;

import java.lang.reflect.Array;
import java.math.BigInteger;

import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.FlowType;

public class EX9ITDisassembler {
	private Program program;
	private ProgramContext programContext;
	private Language language;
	private Memory memory;
	private final int INSTRUCTION_TABLE_ENTRY_LENGTH = 4;
	private Register itbReg;
	private Listing listing;
	private Address zeroAddress;
	private final String EX9IT_MNEMONIC = "EX9.IT";

	public EX9ITDisassembler(Program program) {
		this.program = program;
		memory = program.getMemory();
		language = program.getLanguage();
		programContext = program.getProgramContext();
		listing = program.getListing();
		itbReg = language.getRegister("ITB");
		zeroAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
	}

	boolean instructionIsEX9IT(Instruction insn) {
		return insn.getMnemonicString().equals(EX9IT_MNEMONIC);
	}

	public PseudoInstruction disassemble(Address disasmAddr, byte bytes[]) throws InsufficientBytesException,
			UnknownInstructionException {
		PseudoDisassemblerContext disassemblerContext = new PseudoDisassemblerContext(programContext);
		MemBuffer memBuffer = new ByteMemBufferImpl(disasmAddr, bytes, language.isBigEndian());

		// check that address is defined in memory
		try {
			memBuffer.getByte(0);
		} catch (Exception e) {
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
			// First, normal decode
			instr = new PseudoInstruction(program, disasmAddr, prototype, memBuffer, disassemblerContext);

			// hw would generate Reserved Instruction Exception
			if (instructionIsEX9IT(instr)) {
				return null;
			}

			// If it's branch, it's decoded as if current pc is 0
			// Must avoid passing program to PseudoInstruction, otherwise it will read from
			// program at the given addr - which we're trying to avoid
			FlowType flowType = prototype.getFlowType(instr);
			if (flowType.isCall() || flowType.isJump()) {
				instr = new PseudoInstruction(program.getAddressFactory(), zeroAddress, prototype, memBuffer,
						disassemblerContext);
			}
		} catch (AddressOverflowException e) {
			throw new InsufficientBytesException(
					"failed to build pseudo instruction at " + disasmAddr + ": " + e.getMessage());
		}

		return instr;
	}

	Instruction getEX9ITInstruction(Address address) {
		Instruction insn = listing.getInstructionAt(address);
		if (insn == null) {
			return null;
		}
		if (!instructionIsEX9IT(insn)) {
			return null;
		}
		return insn;
	}

	public PseudoInstruction getITInstruction(Instruction ex9itInsn) {
		Address ex9itAddress = ex9itInsn.getAddress();
		long itOffset = ex9itInsn.getScalar(0).getUnsignedValue() * INSTRUCTION_TABLE_ENTRY_LENGTH;

		BigInteger ITB = programContext.getValue(itbReg, ex9itAddress, false);
		if (ITB == null) {
			return null;
		}
		long memOffset = (ITB.longValue() & ~0b11) + itOffset;
		Address fetchAddress = ex9itInsn.getAddress().getNewAddress(memOffset);

		byte[] data = new byte[INSTRUCTION_TABLE_ENTRY_LENGTH];
		try {
			if (memory.getBytes(fetchAddress, data) != Array.getLength(data)) {
				return null;
			}
			return disassemble(ex9itAddress, data);
		} catch (Exception ex) {
			return null;
		}
	}

	public PseudoInstruction getITInstruction(Address ex9itAddress) {
		Instruction ex9Insn = getEX9ITInstruction(ex9itAddress);
		if (ex9Insn == null) {
			return null;
		}
		return getITInstruction(ex9Insn);
	}
}