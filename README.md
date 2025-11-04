# [[PIS] Position-Independent String](https://github.com/mrzaxaryan/PIS)

Many authors call out the same problem: handling strings in Windows shellcode is difficult. Shellcode is normally the raw bytes extracted from a PE file’s .text section — position-independent machine code that runs without the C runtime and typically resolves APIs indirectly rather than using import linkage. Those constraints make embedding, locating, and using strings at runtime a recurring and subtle challenge. In a normal PE, string literals are placed in the read-only data section (.rdata), while writable initialized data appears in .data.

A common workaround is *stack strings*: build or copy the message into stack memory at runtime (byte-wise or with immediate writes), then pass that buffer to APIs. Stack strings hinder static analysis and can be used for obfuscation, but they also complicate development and debugging. If you need runtime logging during development, you must still construct messages dynamically (stack or heap), which increases code size and complexity and can hit practical limits depending on the assembler, calling convention, or available stack space.
```
char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
```
```
#pragma code_seg(".text")

__declspec(allocate(".text"))
char load_lib_str[] = "LoadLibraryA";
```
Another option is a custom loader that maps the PE image and performs manual relocations instead of using the Windows loader. A custom loader gives you full control over where data lives (so you can place strings in writable memory you control) and can simplify runtime addressing. The downsides are obvious: more code, more edge cases to handle and an identifiable fingerprint that may hinder stealth.

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
On x86_64, data and literals are commonly accessed with RIP-relative addressing. That means the instruction encodings hold a displacement relative to the instruction pointer (RIP). If the compiler emits RIP-relative loads for constants and your code is position-independent (compiled/linked as PIC), those displacement operands will point to offsets inside the blob — so moving .rdata into .text generally will work. In other words, the code continues to find data via PC-relative offsets inside the single contiguous blob.

x86 (32-bit):
To make this approach work on x86 you must perform relocations manually in the shellcode. On 32-bit PE images data references are usually stored as relocations that the Windows loader fixes up to a process virtual address. So your shellcode needs a small relocation pass at runtime that changes each relocated value to (blob_base + offset) (or otherwise applies the image base delta).
First, the shellcode must discover its mapped base address (the runtime address of the blob). One way to get a current code address at the entry point is to read the return address / instruction pointer. Then scan nearby bytes for a known prologue.  
```
#define GetBaseAddress() (*(PVOID*)((BYTE*)__readfsdword(0x30) + 0x10))
#define SetBaseAddress(v) (*(PVOID*)((BYTE*)__readfsdword(0x30) + 0x10) = (v))
#define Relocate(s) (GetBaseAddress() + s)

//...

char* currentAddress = (char*)_ReturnAddress();
// 55              push ebp
// 89 e5           mov ebp, esp First 3 byte of shellcode
while (!(currentAddress[0] == 0x55 && currentAddress[1] == 0x89 && currentAddress[2] == 0xe5)) {
    currentAddress--;
}
SetBaseAddress(currentAddress);

char* strInvalid = "Hello World!";  // raw in the blob — in x86 this is an offset, not a valid pointer
char* fixedStr = Relocate(str); // compute runtime pointer: blob_base + offset
char* strValid = Relocate("Hello World!");

```
