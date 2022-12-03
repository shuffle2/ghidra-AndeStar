# Ghidra extension for Andes Technology AndeStar ISA

This covers V1-V3 of the ISA. V5 changed to RISC-V which would be supported by a RISC-V Ghidra extension.

Currently only instructions I've seen used in practice are supported. PRs accepted of course.

## Manuals

ISA documentation can be found at http://www.andestech.com/en/products-solutions/product-documentation/  
Of interest are:
* "AndeStar ISA Manual" (AndeStar_ISA_UM025_V2.2.pdf)
  * defines ISA encoding and semantics
* "AndeStar SPA V3 Manual" (AndeStar_SPA_V3_UM072_V1.8.pdf)
  * defines System Registers

## Use

Ensure `GHIDRA_INSTALL_DIR` and `JAVA_HOME` environment variables are set, if needed.

```bash
cd ghidra/Ghidra/Processors
git clone https://github.com/shuffle2/ghidra-AndeStar AndeStar
cd AndeStar
gradle
```

The generated `.zip` in `dist` should then be extracted to `${GHIDRA_INSTALL_DIR}/Ghidra/Processors`.
