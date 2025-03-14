# TESTERS NEEDED!
This IDAPython port is experimental, i need testers to confirm that the mentioned instructions are being supported correctly.

# PowerPC Altivec/VMX Extension Module

The PowerPC processor module in IDA Pro does not handle Altivec/VMX instructions. Many
well-known PowerPC implementations include support for Altivec (such as the Apple G4/G5 range,
or the majority of next generation game consoles). Fortunately IDA Pro supports the concept of
extension modules that can add support for non-standard instructions, so this extension adds
support for the Altivec instruction set.

INSTALLATION
------------
Place the `.py` and `.json` file inside `plugins` folder of IDA

Plugin is enabled by default, can be disabled through `CTRL+H` shortcut or `Edit > Plugins` section




CHANGELOG
------------
#### 27.03.05 - Dean - V1.0
* Created

#### 14.05.05 - Dean - V1.1
* Correction to operand register number extraction.
* Correction to operand order for vmaddfp.
* Now handles initial analysis without any additional hassle.
* Added support for Altivec opcodes with 4 parameters.

#### 22.05.05 - Dean - V1.2
* Added support for auto comments.

#### 26.09.05 - Dean - V1.3
* Support for IDA Pro 4.9

#### 07.12.10 - xorloser - V1.8
* Support for Gekko instructions merged from the Gekko extension module created by HyperIris.
* Also incldued support for SPRG names for PS3 as added by Tridentsx.

#### 12.03.18  yui-konnu   V1.9
* Support for IDA 7. Added SPRG descriptions to auto-comments.

#### 03.04.18  yui-konnu   V1.9.1
* Added Linux/macOS build methods.

#### 08.06.18  yui-konnu   V1.9.1
* Added CMake build file.

#### 14.03.25  Fabx        V1.9.1a
* Port to IDAPython for IDA Pro 9.x
