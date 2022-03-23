#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <stdio.h>
#include <iostream>
#include <map>
#include <string.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include "flatbuffers/flatbuffers.h"
#include "trace_generated.h"

namespace py = pybind11;
#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)

typedef uintptr_t EventHandle;

const EventHandle invalid_event_handle = (EventHandle)(-1);
const unsigned int vcpu_any = -1;

struct State {
    size_t ev_count;
    EventHandle ev;
    std::unordered_map<uint64_t, uint8_t> mem;
};

class NativeTrace {
protected:
    uint8_t *m_data;
    size_t m_size;
    EventHandle m_first_event;
    EventHandle m_last_event;

public:
    NativeTrace(int fd, size_t size) {
        m_size = size;
        if (m_size) {
            m_data = (uint8_t*)mmap(0, m_size, PROT_READ, MAP_PRIVATE, fd, 0);
            assert(m_data);
            m_first_event = (EventHandle)(0);
            size_t last_sz = *(uint32_t*)&m_data[m_size-4];
            m_last_event = m_size - last_sz - 2*4;
        } else {
            m_data = NULL;
            m_first_event = invalid_event_handle;
            m_last_event = invalid_event_handle;
        }
    }

    NativeTrace(const std::string &path) {
        FILE *f = fopen(path.c_str(), "rb");
        fseek(f, 0, SEEK_END);
        m_size = ftell(f);
        fseek(f, 0, SEEK_SET);
        int fd = fileno(f);
        m_data = (uint8_t*)mmap(0, m_size, PROT_READ, MAP_PRIVATE, fd, 0);
        assert(m_data);
        fclose(f);
        m_first_event = (EventHandle)(0);
        size_t last_sz = *(uint32_t*)&m_data[m_size-4];
        m_last_event = m_size - last_sz - 2*4;
    }

    ~NativeTrace() {
        munmap(m_data, m_size);
    }

    bool event_handle_invalid(EventHandle ev) {
        return ev == invalid_event_handle;
    }

    EventHandle get_first_event() {
        return m_first_event;
    }

    EventHandle get_last_event() {
        return m_last_event;
    }

    EventHandle get_prev_event(EventHandle ev) {
        if (ev == invalid_event_handle || ev == m_first_event) {
            return invalid_event_handle;
        }
        return (EventHandle)(ev - *(uint32_t *)&m_data[ev-4] - 2*4);
    }

    EventHandle get_next_event(EventHandle ev) {
        if (ev == invalid_event_handle || ev == m_last_event) {
            return invalid_event_handle;
        }
        return (EventHandle)(ev + *(uint32_t *)&m_data[ev] + 2*4);
    }

    size_t get_num_events() {
        size_t c = 0;
        for (EventHandle ev = m_first_event; !event_handle_invalid(ev); ev = get_next_event(ev)) {
            c++;
        }
        return c;
    }

    EventHandle get_nth_event(size_t n) {
        // FIXME: Could be faster seeking from end or from known position
        size_t c = 0;
        for (EventHandle ev = m_first_event; !event_handle_invalid(ev); ev = get_next_event(ev)) {
            if (c++ == n) {
                return ev;
            }
        }
        return invalid_event_handle;
    }

    const Event *handle_to_event(EventHandle handle) {
        return handle == invalid_event_handle ? nullptr : GetEvent(m_data + handle + 4);
    }

    using FilterFn = std::function<bool(EventHandle h)>;
    EventHandle filter(EventHandle start, FilterFn filter_func, bool forward)
    {
        EventHandle ev = start;

        while (!event_handle_invalid(ev)) {
            if (filter_func(ev)) {
                return ev;
            }
            ev = forward ? get_next_event(ev) : get_prev_event(ev);
        }
        return invalid_event_handle;
    }

    bool event_vcpu_match(EventHandle h, unsigned int vcpu) {
        if (vcpu == vcpu_any) return true;

        auto ev = handle_to_event(h);

        /* FIXME: Ugly */

        auto ev0 = ev->event_as_blockEvent();
        if (ev0 != nullptr) return ev0->vcpu() == vcpu;

        auto ev1 = ev->event_as_insnEvent();
        if (ev1 != nullptr) return ev1->vcpu() == vcpu;

        auto ev2 = ev->event_as_memoryEvent();
        if (ev2 != nullptr) return ev2->vcpu() == vcpu;

        auto ev3 = ev->event_as_syscallEvent();
        if (ev3 != nullptr) return ev3->vcpu() == vcpu;

        auto ev4 = ev->event_as_syscallRetEvent();
        if (ev4 != nullptr) return ev4->vcpu() == vcpu;

        auto ev5 = ev->event_as_vcpuInitEvent();
        if (ev5 != nullptr) return ev5->vcpu() == vcpu;

        auto ev6 = ev->event_as_vcpuExitEvent();
        if (ev6 != nullptr) return ev6->vcpu() == vcpu;

        return true;
    }

    EventHandle filter_exec_addr(EventHandle start, uint64_t addr, bool forward, unsigned int vcpu) {
        return filter(start, [=](EventHandle h) {
            auto ev = handle_to_event(h)->event_as_insnEvent();
            return ev != nullptr && ev->addr() == addr && event_vcpu_match(h, vcpu);
        }, forward);
    }

    EventHandle filter_memory(EventHandle start, uint64_t addr, uint64_t size, bool store, bool forward, unsigned int vcpu) {
        return filter(start, [=](EventHandle h) {
            auto ev = handle_to_event(h)->event_as_memoryEvent();
            if (ev == nullptr || store != ev->isStore()) return false;
            if (!event_vcpu_match(h, vcpu)) return false;
            uint64_t event_addr = ev->addr();
            uint64_t event_sz = ev->data() ? ev->data()->size() : 1 << ev->size();
            uint64_t event_end = event_addr + event_sz; /* XXX: Wrap */
            uint64_t end = addr + size;
            bool intersect = !(event_addr >= end || addr >= event_end);
            return intersect;
        }, forward);
    }

    EventHandle filter_type(EventHandle start, int type, bool forward, unsigned int vcpu) {
        return filter(start, [=](EventHandle h) {
            return handle_to_event(h)->event_type() == type && event_vcpu_match(h, vcpu);
        }, forward);
    }

    State replay_from_state_until(const State &initial_state, EventHandle until) {
        State state(initial_state);

        while (!event_handle_invalid(state.ev)) {
            // Apply event effects up to but not including stop event
            if (state.ev >= until) break;

            auto rev = handle_to_event(state.ev);
            if (rev->event_type() == EventUnion_memoryEvent) {
                auto ev = rev->event_as_memoryEvent();
                const uint8_t *bytes;
                uint64_t sz;
                uint64_t v;

                if (ev->data()) {
                    sz = ev->data()->size();
                    bytes = ev->data()->data();
                } else {
                    v = ev->value();
                    sz = 1 << ev->size();
                    assert(sz <= 8);
                    bytes = (uint8_t*)&v; // XXX: Portability
                }

                for (size_t i = 0; i < sz; i++) {
                    state.mem[ev->addr() + i] = bytes[i];
                }
            } else if (rev->event_type() == EventUnion_insnEvent) {
                auto ev = rev->event_as_insnEvent();
                const uint8_t *bytes = ev->bytes()->data();
                uint64_t sz = ev->bytes()->size();
                for (size_t i = 0; i < sz; i++) {
                    state.mem[ev->addr() + i] = bytes[i];
                }
            }

            state.ev_count++;
            state.ev = get_next_event(state.ev);
        }

        return state;
    }

    State replay_until(EventHandle until) {
        State state;
        state.ev_count = 0;
        state.ev = m_first_event;
        return replay_from_state_until(state, until);
    }

    State replay() {
        return replay_until(invalid_event_handle);
    }
};

PYBIND11_MODULE(bintrace_native, m) {
    m.doc() = R"pbdoc(
        bintrace_native
        ----------
        Native trace file management

        .. currentmodule:: bintrace_native

        .. autosummary::
           :toctree: _generate
    )pbdoc";

    py::class_<State>(m, "State")
        .def(py::init<>())
        .def_readonly("ev", &State::ev)
        .def_readonly("ev_count", &State::ev_count)
        .def_readonly("mem", &State::mem)
        .def("__getitem__", [](const State &self, size_t i) { return self.mem.at(i); })
        .def("__copy__",  [](const State &self) { return State(self); })
        ;

    py::class_<NativeTrace>(m, "NativeTrace")
        .def(py::init<int, size_t>())
        .def("event_handle_invalid", &NativeTrace::event_handle_invalid)
        .def("get_first_event", &NativeTrace::get_first_event)
        .def("get_last_event", &NativeTrace::get_last_event)
        .def("get_prev_event", &NativeTrace::get_prev_event)
        .def("get_next_event", &NativeTrace::get_next_event)
        .def("get_num_events", &NativeTrace::get_num_events)
        .def("get_nth_event", &NativeTrace::get_nth_event)
        .def("replay", &NativeTrace::replay)
        .def("replay_from_state_until", &NativeTrace::replay_from_state_until)
        .def("replay_until", &NativeTrace::replay_until)
        .def("filter_type", &NativeTrace::filter_type)
        .def("filter_exec_addr", &NativeTrace::filter_exec_addr)
        .def("filter_memory", &NativeTrace::filter_memory)
        ;

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}
