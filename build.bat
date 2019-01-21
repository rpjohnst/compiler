@echo off
rem cl /nologo /permissive- /volatile:iso /W4 /WX /EHa- /GR- /GS- /Zl /utf-8 /O2 /GL /Gw /Zi /Zo /Zf /D_AMD64_ /DUNICODE compiler.c /link /WX /subsystem:console /dynamicbase:no /fixed /opt:ref,icf /incremental:no /debug:fastlink /pdbaltpath:%%_PDB%% /novcfeature /nocoffgrpinfo kernel32.lib
clang-cl /permissive- /volatile:iso /W4 -Wconversion /WX /EHa- /GR- /GS- /Zl /utf-8 /O2 -flto=thin /Gw /Zi /Zo /D_AMD64_ /DUNICODE compiler.c -fuse-ld=lld /link /WX /subsystem:console /dynamicbase:no /fixed /opt:ref,icf /incremental:no /pdbaltpath:compiler.pdb /entry:mainCRTStartup kernel32.lib
