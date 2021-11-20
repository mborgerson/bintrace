#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <capnp/message.h>
#include <capnp/serialize-packed.h>

#include "trace.capnp.h"

static int out_fd = 2;
// FIXME: Add mutex

static void output_message(::capnp::MessageBuilder& builder)
{
    writePackedMessageToFd(out_fd, builder);
}

extern "C" {
#include <qemu-plugin.h>
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void vcpu_user_write(qemu_plugin_id_t id, unsigned int vcpu_idx,
                            uint64_t vaddr, void *data, size_t len);
static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_index,
                         int64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                         uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                         uint64_t a8);
static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, uint64_t val, void *udata);
static void vcpu_insn_exec(unsigned int cpu_index, void *udata);
static void vcpu_tb_exec(unsigned int cpu_index, void *udata);
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);
static void plugin_exit(qemu_plugin_id_t id, void *p);
static void image_map_cb(qemu_plugin_id_t id, const char *image_name, uint64_t offset, uint64_t base, uint64_t len);
};

static void vcpu_user_write(qemu_plugin_id_t id, unsigned int vcpu_idx,
                            uint64_t vaddr, void *data, size_t len)
{
    uint8_t *bytes = (uint8_t*)data;

    ::capnp::MallocMessageBuilder msg;
    auto ev = msg.initRoot<Event>().initMemoryEvent();
    ev.setVcpu(vcpu_idx);
    ev.setAddr(vaddr);
    ev.setIsStore(true);
    ev.initBytes(len);
    ev.setBytes(kj::arrayPtr(bytes, len));
    output_message(msg);
}

static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_idx,
                         int64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                         uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                         uint64_t a8)
{
    ::capnp::MallocMessageBuilder msg;
    auto ev = msg.initRoot<Event>().initSyscallEvent();
    ev.setVcpu(vcpu_idx);
    ev.setNum(num);
    output_message(msg);
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx,
                             int64_t num, int64_t ret)
{

    ::capnp::MallocMessageBuilder msg;
    auto ev = msg.initRoot<Event>().initSyscallRetEvent();
    ev.setVcpu(vcpu_idx);
    ev.setNum(num);
    ev.setRet(ret);
    output_message(msg);
}

static void vcpu_mem(unsigned int vcpu_idx, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, uint64_t val, void *udata)
{
    struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr) {
        g_assert(0);
        // uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
        // const char *name = qemu_plugin_hwaddr_device_name(hwaddr);
        // g_string_append_printf(s, ", 0x%"PRIx64", %s", addr, name);
    }

    ::capnp::MallocMessageBuilder msg;
    auto ev = msg.initRoot<Event>().initMemoryEvent();
    ev.setIsStore(qemu_plugin_mem_is_store(info));
    ev.setVcpu(vcpu_idx);
    ev.setAddr(vaddr);
    switch (qemu_plugin_mem_size_shift(info)) {
    case 0: ev.setUi8(val); break;
    case 1: ev.setUi16(val); break;
    case 2: ev.setUi32(val); break;
    case 3: ev.setUi64(val); break;
    default: g_assert(0);
    }
    output_message(msg);
}

struct insn_info {
    uint64_t       vaddr;
    const char    *mnem;
    size_t         len;
    const uint8_t *bytes;
};

static void vcpu_insn_exec(unsigned int vcpu_idx, void *udata)
{
    struct insn_info *info = (struct insn_info *)udata;

    ::capnp::MallocMessageBuilder msg;
    auto ev = msg.initRoot<Event>().initInsnEvent();
    ev.setVcpu(vcpu_idx);
    ev.setAddr(info->vaddr);
    ev.setMnem(info->mnem);
    ev.setBytes(kj::arrayPtr(info->bytes, info->len));
    output_message(msg);
}

static void vcpu_tb_exec(unsigned int vcpu_idx, void *udata)
{
    struct qemu_plugin_register_desc desc;
    uint64_t pc = (uint64_t)udata;

    ::capnp::MallocMessageBuilder msg;
    auto ev = msg.initRoot<Event>().initBlockEvent();
    ev.setVcpu(vcpu_idx);
    ev.setAddr(pc);
    auto regs = ev.initRegs(18);
    for (int i = 0; i < 18; i++) {
        bool success = qemu_plugin_get_register(vcpu_idx, i, &desc);
        if (!success) {
            break;
        }
        regs.set(i, desc.data_64u);
    }
    output_message(msg);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;

    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        insn = qemu_plugin_tb_get_insn(tb, i);

        struct insn_info *info;
        info = (struct insn_info *)malloc(sizeof(*info));
        g_assert(info);
        info->vaddr = qemu_plugin_insn_vaddr(insn);
        info->mnem = qemu_plugin_insn_disas(insn);
        info->len = qemu_plugin_insn_size(insn);
        uint8_t *bytes = (uint8_t *)malloc(info->len);
        g_assert(bytes);
        memcpy(bytes, qemu_plugin_insn_data(insn), info->len);
        info->bytes = bytes;

        /* Register callback on memory read or write */
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, NULL);

        /* Register callback on instruction */
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, info);
    }

    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)pc);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
}

static void image_map_cb(qemu_plugin_id_t id, const char *image_name, uint64_t offset, uint64_t base, uint64_t len)
{
    ::capnp::MallocMessageBuilder msg;
    auto ev = msg.initRoot<Event>().initImageMapEvent();
    ev.setName(image_name);
    ev.setOffset(offset);
    ev.setBase(base);
    ev.setLen(len);
    output_message(msg);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    if (argc > 0) {
        char *out_path = argv[0];
        int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            fprintf(stderr, "Failed to open file '%s' for trace writing\n", out_path);
            exit(1);
        }
        out_fd = fd;
    }

    qemu_plugin_register_image_map_cb(id, image_map_cb);
    qemu_plugin_register_vcpu_user_write_cb(id, vcpu_user_write);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
