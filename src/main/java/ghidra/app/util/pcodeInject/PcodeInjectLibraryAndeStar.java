package ghidra.app.util.pcodeInject;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryAndeStar extends PcodeInjectLibrary {
	// names of defined pcode ops that require pcode injection
	public static final String LMW = "lmw";
	public static final String SMW = "smw";
	public static final String EX9IT = "ex9it";

	private Map<String, InjectPayloadCallother> implementedOps;

	public static final String SOURCENAME = "AndeStarInternal";

	public PcodeInjectLibraryAndeStar(SleighLanguage l) {
		super(l);
		implementedOps = new HashMap<>();
		implementedOps.put(LMW, new InjectLSMW(SOURCENAME, l, uniqueBase, false));
		uniqueBase += 0x100;
		implementedOps.put(SMW, new InjectLSMW(SOURCENAME, l, uniqueBase, true));
		uniqueBase += 0x100;
		implementedOps.put(EX9IT, new InjectEX9IT(SOURCENAME));
		uniqueBase += 0x100;
	}

	public PcodeInjectLibraryAndeStar(PcodeInjectLibraryAndeStar op2) {
		super(op2);
		implementedOps = op2.implementedOps; // Immutable
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryAndeStar(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			InjectPayloadCallother payload = implementedOps.get(name);
			if (payload != null) {
				return payload;
			}
		}
		return super.allocateInject(sourceName, name, tp);
	}
}
