# [PIS Position-Independent String](https://github.com/mrzaxaryan/PIS)

Many authors call out the same problem: handling strings in Windows shellcode is difficult. Shellcode is normally the raw bytes extracted from a PE file’s .text section — position-independent machine code that runs without the C runtime and typically resolves APIs indirectly rather than using import linkage. Those constraints make embedding, locating, and using strings at runtime a recurring and subtle challenge. In a normal PE, string literals are placed in the read-only data section (.rdata), while writable initialized data appears in .data.

A common workaround is stack strings: build or copy the message into stack memory at runtime (byte-wise or with immediate writes), then pass that buffer to APIs. Stack strings hinder static analysis and can be used for obfuscation, but they also complicate development and debugging. If you need runtime logging during development, you must still construct messages dynamically (stack or heap), which increases code size and complexity and can hit practical limits depending on the assembler, calling convention, or available stack space.

Another option is a custom loader that maps the PE image and performs manual relocations instead of using the Windows loader. A custom loader gives you full control over where data lives (so you can place strings in writable memory you control) and can simplify runtime addressing. The downsides are obvious: more code, more edge cases to handle (imports, relocations, TLS), and an identifiable fingerprint that may hinder stealth.

So what can we do? Let’s be explicit: the PE contains several sections, but when we extract only .text we get the raw machine instructions. One trick is to force .data / .rdata contents into the .text output by the linker. For example:
```
SECTIONS
{
    /* .text at 0x0, 1-byte aligned */
    .text 0x0 : ALIGN(1) SUBALIGN(1)
    {
        *(.text$mainCRTStartup)
        *(.text*)
        *(.data*)                       /* initialized global/static data */
        *(.rdata*)                      /* read-only initialized data (constants) */
    }
}
```

This produces a PE whose .text raw bytes include the data and read-only literals. The resulting PE is technically invalid in a normal sense (sections and headers no longer reflect usual characteristics), but when you extract the .text raw bytes and use those bytes as your shellcode blob the embedded data will be present inside the blob.

Technical analysis — will this actually work?

x86_64 (64-bit):
On x86_64, data and literals are commonly accessed with RIP-relative addressing. That means the instruction encodings hold a displacement relative to the instruction pointer (RIP). If the compiler emits RIP-relative loads for constants and your code is position-independent (compiled/linked as PIC), those displacement operands will point to offsets inside the blob — so moving .rdata into .text generally can work. In other words, the code continues to find data via PC-relative offsets inside the single contiguous blob.

x86 (32-bit):
On 32-bit x86 there is no RIP register and most compilers emit absolute or absolute-indirect data references (or use the global offset table in PIC builds). Typical non-PIC 32-bit code will use absolute addresses or depend on base registers set up by the loader. Simply merging .rdata into .text will usually break those absolute references — they’ll point to addresses the shellcode blob does not occupy. You would need to either:
