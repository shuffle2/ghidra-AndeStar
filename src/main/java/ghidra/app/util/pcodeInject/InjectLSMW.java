package ghidra.app.util.pcodeInject;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class InjectLSMW extends InjectPayloadCallother {
	private SleighLanguage language;
	private long uniqueBase;
	private boolean store;
	private AddressSpace constSpace;
	private AddressSpace uniqueSpace;
	private Address opAddress;
	private int seqnum;
	private Varnode defSpaceId;

	public InjectLSMW(String sourceName, SleighLanguage language, long uniqueBase, boolean store) {
		super(sourceName);
		this.language = language;
		this.uniqueBase = uniqueBase;
		this.store = store;
		constSpace = language.getAddressFactory().getConstantSpace();
		uniqueSpace = language.getAddressFactory().getUniqueSpace();
		defSpaceId = getConstant(language.getDefaultSpace().getSpaceID(), 4);
		seqnum = 0;
	}

	private Varnode convertRegisterToVarnode(Register reg) {
		return new Varnode(reg.getAddress(), reg.getBitLength() / 8);
	}

	private Varnode getConstant(long val, int size) {
		return new Varnode(constSpace.getAddress(val), size);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		int Rb = (int) con.inputlist.get(0).getOffset();
		Varnode Ra = con.inputlist.get(1);
		int Re = (int) con.inputlist.get(2).getOffset();
		int Enable4 = (int) con.inputlist.get(3).getOffset();
		int BeforeAfter = (int) con.inputlist.get(4).getOffset();
		int IncDec = (int) con.inputlist.get(5).getOffset();
		int Modify = (int) con.inputlist.get(6).getOffset();

		boolean noRegs = Rb == Re && Rb == 31;
		if (Rb > Re || (!noRegs && Rb > 28) || (noRegs && Enable4 == 0)) {
			throw new IllegalArgumentException("illformed lsmw");
		}

		int reglist = Enable4;
		if (!noRegs) {
			for (int i = Rb; i <= Re; i++) {
				reglist |= 1 << (31 - i);
			}
		}
		int totalSize = 0;
		for (int i = 0; i < 32; i++) {
			if ((reglist & (1 << i)) != 0) {
				totalSize += 4;
			}
		}

		opAddress = con.baseAddr;
		ArrayList<PcodeOp> opList = new ArrayList<PcodeOp>();

		int RaSize = Ra.getSize();
		Varnode regSize = getConstant(RaSize, RaSize);
		Varnode numBytes = getConstant(totalSize, RaSize);

		// bAddr = Ra
		Varnode bAddr = new Varnode(uniqueSpace.getAddress(uniqueBase), RaSize);
		uniqueBase += 16; // ?
		opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.COPY, new Varnode[] { Ra }, bAddr));

		// int b_addr;
		if (BeforeAfter == 0 && IncDec == 0) {
			// b_addr = Ra;
		} else if (BeforeAfter != 0 && IncDec == 0) {
			// b_addr = Ra + 4;
			opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, new Varnode[] { bAddr, regSize }, bAddr));
		} else if (BeforeAfter == 0 && IncDec != 0) {
			// b_addr = Ra - totalSize + 4;
			opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SUB, new Varnode[] { bAddr, numBytes }, bAddr));
			opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, new Varnode[] { bAddr, regSize }, bAddr));
		} else {
			// b_addr = Ra - totalSize;
			opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SUB, new Varnode[] { bAddr, numBytes }, bAddr));
		}

		Address a0Addr = language.getRegister("a0").getAddress();
		for (int i = 0; i < 32; i++) {
			if ((reglist & (1 << (31 - i))) == 0) {
				continue;
			}
			Varnode reg = convertRegisterToVarnode(language.getRegister(a0Addr.add(i * RaSize), RaSize));
			if (store) {
				// generate the store from R[i]
				opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.STORE, new Varnode[] { defSpaceId, bAddr, reg }));
			} else {
				// generate the load to R[i]
				opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.LOAD, new Varnode[] { defSpaceId, bAddr }, reg));
			}
			// b_addr += 4;
			opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, new Varnode[] { bAddr, regSize }, bAddr));
		}

		// BUG: the writeback does not flow to the successive instructions for some
		// reason. Because the inject type is CALLOTHERFIXUP_TYPE?
		/*
		 * if (Modify != 0) {
		 * if (IncDec == 0) {
		 * // Ra += totalSize;
		 * opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, new Varnode[] {
		 * Ra, numBytes }, Ra));
		 * } else {
		 * // Ra -= totalSize;
		 * opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SUB, new Varnode[] {
		 * Ra, numBytes }, Ra));
		 * }
		 * }
		 * //
		 */

		PcodeOp[] res = new PcodeOp[opList.size()];
		opList.toArray(res);
		return res;
	}

}
