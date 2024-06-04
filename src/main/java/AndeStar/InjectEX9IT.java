package AndeStar;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;

public class InjectEX9IT extends InjectPayloadCallother {
	private SleighLanguage language;
	private AddressSpace defaultSpace;
	private CodeUnitFormat formatter;

	public InjectEX9IT(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName);
		this.language = language;
		defaultSpace = language.getAddressFactory().getDefaultAddressSpace();
		formatter = new CodeUnitFormat(new CodeUnitFormatOptions());
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		int imm9u = (int) con.inputlist.get(0).getOffset();

		Address ITB = language.getRegister("ITB").getAddress();
		// TODO get VALUE of ITB reg. note the address has the offset into register space
		ITB = ITB.getNewAddress(0xa38c);
		long offset = (ITB.getOffset() & ~0b11) + imm9u * 4;
		Address insn_addr = defaultSpace.getAddress(offset);

		PseudoInstruction insn = null;
		PseudoDisassembler disassembler = new PseudoDisassembler(program);
		try {
			insn = disassembler.disassemble(insn_addr);
		} catch (Exception ex) {
			throw new IllegalArgumentException("disasm " + insn_addr.toString() + " " + ex.getMessage());
		}
		// could be bad ITB
		if (insn == null) {
			throw new IllegalArgumentException("insn null " + insn_addr.toString());
		}
		// check insn isn't another ex9it (this probably works on hw, but we want to
		// prevent unbounded recursion)
		if (insn.getMnemonicString() == "EX9.IT") {
			throw new IllegalArgumentException("recursive EX9.IT " + insn_addr.toString());
		}

		// TODO append the indirect mnemonic to disasm output somehow
		// insn.addMnemonicReference(con.baseAddr, RefType.THUNK, SourceType.DEFAULT);
		String insn_string = formatter.getRepresentationString(insn);
		program.withTransaction("set EX9.IT comment", () -> {
			program.getListing().setComment(con.baseAddr, CodeUnit.EOL_COMMENT, "{" + insn_string + "}");
		});

		return insn.getPcode();
	}

}
