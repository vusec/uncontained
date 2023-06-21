#include <linux/printk.h>
#include <linux/instruction_pointer.h>
#include <asm/types.h>
#include <asm/page_types.h>
#include <linux/memblock.h>
#include <linux/kasan.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/err.h>
#include <kasan.h>
#include "vanilla_list.h"
#include "percpu-internal.h"

// set to true when kasan has initialized global poisons
extern bool __asan_globals_ready;

// check if the address is reserved by the boot memory allcator (memblock)
// since kasan does not cover those
static bool is_boot_memory(char* addr) {
  phys_addr_t phys_addr;

  // if addr is not in the physmap, it cannot be in boot memory
  if (((unsigned long)addr < PAGE_OFFSET || (unsigned long)addr >= (PAGE_OFFSET + get_max_mapped())))
    return false;

  phys_addr = (unsigned long)addr - PAGE_OFFSET;
  return memblock_is_reserved(phys_addr);
}

// return true if the address is allocated in the percpu memory region, that has
// no fine-grained KASAN redzones
static bool is_percpu_memory(unsigned long addr) {
  int slot;
  struct pcpu_chunk *chunk;

  if (is_kernel_percpu_address(addr) || is_module_percpu_address(addr)) 
    return true;

  for (slot = 0; slot < pcpu_nr_slots; slot++) {
    list_for_each_entry(chunk, &pcpu_chunk_lists[slot], list) {
      if (addr >= (unsigned long)chunk->base_addr && addr < ((unsigned long)chunk->base_addr + chunk->nr_pages*PAGE_SIZE))
        return true;
    }
  }
  return false;
}

bool __used kasan_memory_is_accessible(char* addr)
{
  s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void*)addr);

  if (unlikely(shadow_value)) {
    s8 last_accessible_byte = ((unsigned long)addr) & KASAN_GRANULE_MASK;
    return unlikely(last_accessible_byte < shadow_value);
  }

  return true;
}

static noinline void uncontained_report(char* addr, size_t size, unsigned long ip) {
  pr_err("[UNCONTAINED] Unexpected type at address %px\n", addr);
  pr_err("[UNCONTAINED] %px[0x0-1]: %s\n", addr, !kasan_memory_is_accessible(addr - 1)? "OK poison" : "KO valid");
  pr_err("[UNCONTAINED] %px[0x0]: %s\n", addr, kasan_memory_is_accessible(addr)? "OK valid" : "KO poison");
  pr_err("[UNCONTAINED] %px[0x%lx-1]: %s\n", addr, size, kasan_memory_is_accessible(addr + size - 1)? "OK valid" : "KO poison");
  pr_err("[UNCONTAINED] %px[0x%lx]: %s\n", addr, size, !kasan_memory_is_accessible(addr + size)? "OK poison" : "KO valid");
#ifndef DISABLE_PRINTING
  kasan_report((unsigned long) addr, 1, false, ip);
#endif
}

// Sanitizer check for container_of to check that addr
// has the right size and position in the redzone
// [--------object--------][--------redzone--------]
// ^                      ^^
// |                      ||
// addr       addr+size-1-  - redzone_start
// =====must be valid=====  === must be poisoned====
// orig_addr holds the original pointer we are checking to take into account edge
// cases as ERR values or NULL
// returns true if the type is valid
bool __used uncontained_type_check(char* orig_addr, char* addr, unsigned long size) {

  // bail out if we are during boot and kasan is still not ready
  if (unlikely(!__asan_globals_ready)) {
    return true;
  }

  // bail out if `addr` == NULL or IS_ERR(addr), since we may be in a path not strictly coming
  // from a container_of, but a forwarded use that may depend on something else
  // e.g., return phi(container_of: found_bb, NULL or -EINVAL: not_found_bb)
  if (unlikely(IS_ERR_OR_NULL((void*) orig_addr) || (unsigned long) orig_addr < 0x1000)) {
    return true;
  }

  // bail out if the object is in boot memory
  if (unlikely(is_boot_memory(orig_addr))) {
    return true;
  }

  // report if the address may overflow
  if (unlikely(addr + size < addr)) {
    return false;
  }

  // report if the address has no kasan mapping
  if (unlikely((void *)addr <
      kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
    return false;
  }

  if (unlikely(
    // check for the valid start
    !kasan_memory_is_accessible(addr) || 
    // check for the last byte valid
    !kasan_memory_is_accessible(addr + size - 1) || 
    // check for the first byte of redzone
    kasan_memory_is_accessible(addr + size) 
  )) {
    // actually report only if it is not percpu allocated memory
    if (!is_percpu_memory((unsigned long) addr))
      return false;
  }

  // if it is not a global object, then check the left redzone
  if (unlikely(
    // skip page aligned addresses as it may be the first heap object of a cache
    ((unsigned long)addr & (PAGE_SIZE-1)) != 0 &&
    // not in kernel data
    !is_kernel((unsigned long)orig_addr) &&
    // check for the first left byte of redzone
    kasan_memory_is_accessible(addr - 1)
  )) {
    // actually report only if it is not percpu allocated memory and not module data
    if (!is_percpu_memory((unsigned long) orig_addr) && !is_module_address((unsigned long)orig_addr))
      return false;
  }
  // the type is valid
  return true;
}

// returns uncontained_report, or true in case we are not supposed to check
bool __used uncontained_type_maybe_check(char* orig_addr, char* addr, unsigned long size, bool should_check) {
  if (should_check) {
    return uncontained_type_check(orig_addr, addr, size);
  } else {
    return true;
  }
}

void __used uncontained_type_maybe_report(char* addr, unsigned long size, bool is_safe) {
  if (!is_safe) {
    uncontained_report(addr, size, _RET_IP_);
  }
}
