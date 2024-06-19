package ghidra.app.util.pcodeInject;

import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.app.util.PseudoInstruction;
import plugin.core.analysis.EX9ITDisassembler;

public class InjectEX9IT extends InjectPayloadCallother {

	public InjectEX9IT(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		EX9ITDisassembler disassembler = new EX9ITDisassembler(program);
		PseudoInstruction itInsn = disassembler.getITInstruction(con.baseAddr);
		// Could be bad ITB
		if (itInsn == null) {
			return null;
		}

		// NOTE SymbolicPropogator must be patched to allow STORE pcode ops
		return itInsn.getPcode();
	}

}
