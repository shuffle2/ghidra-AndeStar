package plugin.core.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AndeStarEX9ITAnalyzer extends AbstractAnalyzer {
    private final static String PROCESSOR_NAME = "AndeStar";
    private final static String NAME = "AndeStar EX9IT Analyzer";
    private final static String DESCRIPTION = "Annotates EX9.IT instructions";

    private final static CodeUnitFormat codeUnitFormat = new CodeUnitFormat(new CodeUnitFormatOptions());

    public AndeStarEX9ITAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor().equals(
                Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        Listing listing = program.getListing();
        ReferenceManager refMgr = program.getReferenceManager();

        EX9ITDisassembler disassembler = new EX9ITDisassembler(program);

        for (Address addr : set.getAddresses(true)) {
            PseudoInstruction itInsn = disassembler.getITInstruction(addr);
            if (itInsn == null) {
                continue;
            }

            // Add a comment
            // TODO append to mnemonic instead?

            // itInsn will not have associated program if it's a branch
            if (itInsn.getProgram() != null) {
                String comment = codeUnitFormat.getRepresentationString(itInsn);
                listing.setComment(addr, CodeUnit.EOL_COMMENT, comment);
            } else {
                // dont really need extra comment - ghidra will add one because of the reference
                // comment = itInsn.getPrimaryReference(0).getToAddress().toString();
            }

            // Copy the references

            refMgr.removeAllReferencesFrom(addr);

            Reference[] refs = itInsn.getReferencesFrom();
            if (refs.length > 0) {
                CodeUnit cu = listing.getCodeUnitAt(addr);
                for (Reference ref : refs) {
                    cu.addMnemonicReference(ref.getToAddress(), ref.getReferenceType(), ref.getSource());
                }
            }
        }

        return false;
    }
}
