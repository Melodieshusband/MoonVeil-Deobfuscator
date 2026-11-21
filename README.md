# Created by: Melodie's husband (Meloten)

<div align="center">

# 🌙 MoonVeil Deobfuscator

**Static + runtime-assisted deobfuscation for VM-protected Luau / Lua scripts**

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-success)
![Luau](https://img.shields.io/badge/runtime-Luau-00A2FF)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Ubuntu-lightgrey)

</div>

---

## ✨ Overview

MoonVeil Deobfuscator takes a protected script and turns it back into readable Lua source. It handles two kinds of input:

| Input type | Detection | Strategy |
|---|---|---|
| **VM-protected scripts** (embedded base64 payload + custom bytecode VM) | A base64 decoder and a payload deserializer are found in the script | Recover the payload, infer the VM layout from its handlers, decode the bytecode and lift it back to Lua |
| **AST-obfuscated scripts** (no payload) | No base64 payload found | Decrypt string literals, fold constants and clean the AST |

Everything is pure Python with **no third-party dependencies**. The only external piece is the bundled [Luau](https://luau.org) binary, used to capture inner VM layers at runtime.

## 🧪 Supported versions

| MoonVeil version | Status |
|---|---|
| **v1.4.5** | ✅ Supported |
| Other versions | 🛠️ Planned |

Only **MoonVeil v1.4.5** is supported right now. Support for many more versions is planned and will be added over time.

## 🔧 How it works

```
 input.lua
    │
    ▼
 parse ──► string decoder + base64 + deserializer detection
    │
    ▼
 extract payload ──► deserialize (built-in Lua interpreter)
    │
    ├──► Luau capture of inner layers (innerdump) ──► deserialize inner payload
    │
    ▼
 dump VM handlers ──► infer proto layout ──► classify opcodes
    │
    ▼
 decode bytecode ──► disassemble ──► lift to Lua ──► restructure control flow
    │
    ▼
 final.lua
```

1. **Front stage** – the script is parsed and its string decoder is evaluated by a small built-in Lua interpreter, so encrypted strings are resolved without executing the whole script.
2. **Payload recovery** – the base64 blob is extracted and passed through the script's own deserializer.
3. **Inner layers** – multi-layer scripts only reveal their real bytecode at runtime. The deserializer is instrumented and run under Luau to capture every buffer it receives.
4. **VM analysis** – handler bodies are dumped, the prototype field layout is inferred, and each opcode handler is classified.
5. **Lifting** – bytecode is decoded, disassembled and lifted to Lua, then `goto`/label soup is converted into structured control flow.

## 📁 Repository layout

```
moonveil-deobfuscator/
├── bin/
│   ├── ubuntu/luau          Luau runtime for Linux
│   └── windows/luau.exe     Luau runtime for Windows
├── src/
│   ├── main.py              Command-line entry point and pipeline
│   ├── lex.py, lparse.py    Lua lexer and parser
│   ├── lemit.py             AST to source emitter
│   ├── luai.py              Built-in Lua interpreter
│   ├── detect.py            Decoder / deserializer detection
│   ├── stages.py            Front stage and payload access
│   ├── strdec.py            String decryption helpers
│   ├── payload.py           Payload decompression
│   ├── innerdump.py         Luau-based inner layer capture
│   ├── vmhandlers.py        VM handler extraction
│   ├── layout.py            Prototype layout inference
│   ├── classifier.py        Opcode classification
│   ├── vmdecode.py          Bytecode decoding and disassembly
│   ├── lift.py              Bytecode to Lua lifter
│   ├── structure.py         Control-flow restructuring
│   ├── cff.py               Dispatcher condition helpers
│   ├── passes.py            AST walking and constant folding
│   ├── resolve.py           Block resolution passes
│   └── ast_deobf.py         AST-only deobfuscation path
├── .gitattributes
├── .gitignore
└── README.md
```

## 🚀 Getting started

### Requirements

- Python **3.11+**
- Nothing else. Luau binaries for Windows and Ubuntu are included in `bin/`.

### Run

```bash
git clone https://github.com/<your-name>/moonveil-deobfuscator.git
cd moonveil-deobfuscator
python src/main.py path/to/obfuscated.lua -o out
```

On Windows:

```powershell
python src\main.py path\to\obfuscated.lua -o out
```

### Options

| Flag | Description |
|---|---|
| `input` | Path to the obfuscated script |
| `-o`, `--output` | Output directory (default: `out`) |
| `--luau` | Path to a custom Luau binary, overrides auto-detection |

### Luau detection order

1. The path passed with `--luau`
2. The bundled binary for your OS (`bin/windows/luau.exe` or `bin/ubuntu/luau`)
3. A `luau` executable found on your `PATH`

On macOS or other platforms, install Luau yourself and either put it on your `PATH` or pass `--luau`.

## 📦 Output files

All results are written to the output directory.

| File | Content |
|---|---|
| `final.lua` | The deobfuscated script |
| `lifted.lua` | Lifted source before control-flow restructuring |
| `disasm.txt` | Disassembly of the decoded bytecode |
| `handlers.txt` | Extracted VM handler bodies |
| `stage_strings.lua` | Script after string decryption |
| `payload.bin` | Recovered outer payload |
| `proto.json` | Deserialized outer prototype |
| `proto_inner.json` | Deserialized inner prototype (multi-layer scripts) |
| `inner/` | Captured inner buffers and the instrumented script |

AST-only inputs produce `stage_strings.lua` and `final.lua`.

## ⚠️ Safety notes

- Inner-layer capture **executes the target script under Luau** until its deserializer has been called, or until the 120 second timeout. Run unknown scripts inside a VM, container or other isolated environment.
- Use this tool only on scripts you own or are authorized to analyze.

## 🧩 Known limitations

- Variable naming in lifted output is not always perfect. Some registers can end up referenced without a declaration, so review `final.lua` before relying on it.
- A few `goto` statements may remain when control flow cannot be fully structured.
- The AST-only path decrypts strings and folds constants, but does not unflatten control-flow-flattened dispatcher loops.
- Scripts that use VM layouts the classifier has not seen may fail to decode.

## 🤝 Contributing

Issues and pull requests are welcome. When reporting a failing script, include the console output and, if possible, a minimal sample.

## 📄 License

No license has been chosen yet. Add a `LICENSE` file before publishing if you want others to reuse the code.
