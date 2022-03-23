#include <fcntl.h>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include "flatbuffers/flatbuffers.h"
#include "trace_generated.h"

static int out_fd = 2;
pthread_mutex_t out_fd_lock = PTHREAD_MUTEX_INITIALIZER; /* XXX: Replace with spinlock on MMAP'd trace file */

/* XXX: We write the size of the message to the start and end to simplify seeking. Size is assumed to be <4G, however
 * some write events could go over this limit.
 */
static void output_message(const uint8_t *buf, size_t size)
{
    size_t tsize = size+8;
    uint8_t tbuf[tsize];

    uint32_t *s_head = (uint32_t*)&tbuf[0];
    *s_head = (uint32_t)size;

    memcpy(&tbuf[4], buf, size); /* FIXME: memcpy-free version */

    uint32_t *s_tail = (uint32_t*)&tbuf[tsize-4];
    *s_tail = (uint32_t)size;

    pthread_mutex_lock(&out_fd_lock);
    ssize_t r = write(out_fd, tbuf, tsize);
    pthread_mutex_unlock(&out_fd_lock);
    assert(r == tsize);
}

extern "C" {
#include "../qemu/include/qemu/qemu-plugin.h"
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void vcpu_user_write(qemu_plugin_id_t id, unsigned int vcpu_idx,
                            uint64_t vaddr, void *data, size_t size);
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
static void image_map_cb(qemu_plugin_id_t id, const char *image_name, uint64_t offset, uint64_t base, uint64_t size);
};

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_idx)
{
    flatbuffers::FlatBufferBuilder builder(1024);
    builder.Finish(
        CreateEvent(builder, EventUnion_vcpuInitEvent,
            CreateVcpuInitEvent(builder, vcpu_idx).Union()));
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

static void vcpu_exit(qemu_plugin_id_t id, unsigned int vcpu_idx)
{
    flatbuffers::FlatBufferBuilder builder(1024);
    builder.Finish(
        CreateEvent(builder, EventUnion_vcpuExitEvent,
            CreateVcpuExitEvent(builder, vcpu_idx).Union()));
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

static void vcpu_user_write(qemu_plugin_id_t id, unsigned int vcpu_idx,
                            uint64_t vaddr, void *data, size_t size)
{
    uint8_t *bytes = (uint8_t*)data;

    flatbuffers::FlatBufferBuilder builder(1024);
    auto ev_data = builder.CreateVector(bytes, size);
    MemoryEventBuilder ev(builder);
    ev.add_vcpu(vcpu_idx);
    ev.add_addr(vaddr);
    ev.add_isStore(true);
    ev.add_data(ev_data);
    auto e = CreateEvent(builder, EventUnion_memoryEvent, ev.Finish().Union());
    builder.Finish(e);
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_idx,
                         int64_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                         uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7,
                         uint64_t a8)
{
    flatbuffers::FlatBufferBuilder builder(1024);
    builder.Finish(
        CreateEvent(builder, EventUnion_syscallEvent,
            CreateSyscallEvent(builder, vcpu_idx, num).Union()));
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx,
                             int64_t num, int64_t ret)
{
    flatbuffers::FlatBufferBuilder builder(1024);
    builder.Finish(
        CreateEvent(builder, EventUnion_syscallRetEvent,
            CreateSyscallRetEvent(builder, vcpu_idx, num, ret).Union()));
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

static void vcpu_mem(unsigned int vcpu_idx, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, uint64_t val, void *udata)
{
    struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr) {
        // assert(0);
        // uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
        // const char *name = qemu_plugin_hwaddr_device_name(hwaddr);
        // g_string_append_printf(s, ", 0x%"PRIx64", %s", addr, name);
    }

    flatbuffers::FlatBufferBuilder builder(1024);
    builder.Finish(
        CreateEvent(builder, EventUnion_memoryEvent,
            CreateMemoryEvent(builder, vcpu_idx, vaddr,
                qemu_plugin_mem_is_store(info),
                qemu_plugin_mem_size_shift(info),
                val).Union()));
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

struct insn_info {
    uint64_t       vaddr;
    const char    *mnem;
    size_t         size;
    const uint8_t *bytes;
};

static void vcpu_insn_exec(unsigned int vcpu_idx, void *udata)
{
    struct insn_info *info = (struct insn_info *)udata;

    flatbuffers::FlatBufferBuilder builder(1024);
    builder.Finish(
        CreateEvent(builder, EventUnion_insnEvent,
            CreateInsnEvent(builder,
                vcpu_idx, info->vaddr,
                builder.CreateVector(info->bytes, info->size),
                builder.CreateString(info->mnem)).Union()));
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

static void vcpu_tb_exec(unsigned int vcpu_idx, void *udata)
{
    struct qemu_plugin_register_desc desc;
    uint64_t pc = (uint64_t)udata;

    uint64_t regs[18];
    for (int i = 0; i < 18; i++) {
        bool success = qemu_plugin_get_register(vcpu_idx, i, &desc);
        if (!success) {
            break;
        }
        regs[i] = desc.data_64u;
    }

    flatbuffers::FlatBufferBuilder builder(1024);
    builder.Finish(
        CreateEvent(builder, EventUnion_blockEvent,
            CreateBlockEvent(builder, vcpu_idx, pc,
                builder.CreateVector(regs, 18)).Union()));
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;

    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        insn = qemu_plugin_tb_get_insn(tb, i);

        struct insn_info *info;
        info = (struct insn_info *)malloc(sizeof(*info));
        assert(info);
        info->vaddr = qemu_plugin_insn_vaddr(insn);
        info->mnem = qemu_plugin_insn_disas(insn);
        info->size = qemu_plugin_insn_size(insn);
        uint8_t *bytes = (uint8_t *)malloc(info->size);
        assert(bytes);
        memcpy(bytes, qemu_plugin_insn_data(insn), info->size);
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

char *out_path;
int sync_fds[2];

static void fork_prepare_handler(void)
{
    if (out_path) {
        assert(!pipe(sync_fds));
        pthread_mutex_lock(&out_fd_lock);
    }
}

static void fork_parent_handler(void)
{
    if (out_path) {
        /* Wait for child to finish reading the trace into the new trace file */
        char buf;
        assert(!close(sync_fds[1]));
        assert(read(sync_fds[0], &buf, 1) == 1);
        assert(!close(sync_fds[0]));
        pthread_mutex_unlock(&out_fd_lock);
    }
}

static void fork_child_handler(void)
{
    if (out_path) {
        /* Start a new trace from a copy of parent's trace file.
         *
         * FIXME: We don't need to take up so much space on disk. In the future,
         * replace this with intelligence in trace playback to seek between
         * trace files.
         */
        char *path = g_strdup_printf("%s.%d.trace", out_path, getpid());
        int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            fprintf(stderr, "Failed to open file '%s' for trace writing\n", path);
            exit(1);
        }
        free(path);

        off_t bytes_copied = 0;
        off_t bytes_to_copy = lseek(out_fd, 0, SEEK_END);
        assert(bytes_to_copy >= 0);
        lseek(out_fd, 0, SEEK_SET);
        while (bytes_copied < bytes_to_copy) {
            off_t c = sendfile(fd, out_fd, NULL, bytes_to_copy - bytes_copied);
            assert(c >= 0);
            bytes_copied += c;
        }

        char buf = 0;
        assert(!close(sync_fds[0]));
        assert(write(sync_fds[1], &buf, 1) == 1);
        close(sync_fds[1]);
        assert(close(out_fd) == 0);
        out_fd = fd;
        pthread_mutex_unlock(&out_fd_lock);
    }
}

static void image_map_cb(qemu_plugin_id_t id, const char *image_name, uint64_t offset, uint64_t base, uint64_t size)
{
    flatbuffers::FlatBufferBuilder builder(1024);
    builder.Finish(
        CreateEvent(builder, EventUnion_imageMapEvent,
            CreateImageMapEvent(builder,
                builder.CreateString(image_name),
                offset, base, size).Union()));
    output_message(builder.GetBufferPointer(), builder.GetSize());
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    if (argc > 0) {
        out_path = strdup(argv[0]);
        int fd = open(out_path, O_RDWR | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            fprintf(stderr, "Failed to open file '%s' for trace writing\n", out_path);
            exit(1);
        }
        out_fd = fd;
    }

    pthread_atfork(fork_prepare_handler,
                   fork_parent_handler,
                   fork_child_handler);

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_exit_cb(id, vcpu_exit);
    qemu_plugin_register_image_map_cb(id, image_map_cb);
    qemu_plugin_register_vcpu_user_write_cb(id, vcpu_user_write);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
