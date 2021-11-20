@0xae3c84404bd9bf8e;

struct ImageMapEvent {
  name   @0: Text;
  offset @1: UInt64;
  base   @2: UInt64;
  len    @3: UInt64;
}

struct BlockEvent {
  vcpu @0: UInt8;
  addr @1: UInt64;
  regs @2: List(UInt64);
}

struct InsnEvent {
  vcpu  @0: UInt8;
  addr  @1: UInt64;
  bytes @2: Data;
  mnem  @3: Text;
}

struct MemoryEvent {
  vcpu    @0: UInt8;
  addr    @1: UInt64;
  isStore @2: Bool;
  union {
  ui8     @3: UInt8;
  ui16    @4: UInt16;
  ui32    @5: UInt32;
  ui64    @6: UInt64;
  bytes   @7: Data;
  }
}

struct SyscallEvent {
  vcpu  @0: UInt8;
  num   @1: UInt16;
}

struct SyscallRetEvent {
  vcpu @0: UInt8;
  num  @1: UInt16;
  ret  @2: UInt64;
}

struct Event {
  union {
    imageMapEvent   @0: ImageMapEvent;
    blockEvent      @1: BlockEvent;
    insnEvent       @2: InsnEvent;
    memoryEvent     @3: MemoryEvent;
    syscallEvent    @4: SyscallEvent;
    syscallRetEvent @5: SyscallRetEvent;
  }
}
