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

struct State {
    EventHandle ev;
    std::unordered_map<uint64_t, uint8_t> mem;
};

class NativeTraceManager {
protected:
    uint8_t *m_data;
    size_t m_size;
    EventHandle m_first_event;
    EventHandle m_last_event;

public:
    NativeTraceManager(int fd, size_t size) {
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

    ~NativeTraceManager() {
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

    EventHandle filter_exec_addr(EventHandle start, uint64_t addr, bool forward) {
        return filter(start, [=](EventHandle h) {
            auto ev = handle_to_event(h)->event_as_insnEvent();
            return ev != nullptr && ev->addr() == addr;
        }, forward);
    }

    EventHandle filter_memory(EventHandle start, uint64_t addr, uint64_t len, bool store, bool forward) {
        return filter(start, [=](EventHandle h) {
            auto ev = handle_to_event(h)->event_as_memoryEvent();
            if (ev == nullptr || store != ev->isStore()) return false;
            uint64_t event_addr = ev->addr();
            uint64_t event_sz = ev->data() ? ev->data()->size() : 1 << ev->size();
            uint64_t event_end = event_addr + event_sz; /* XXX: Wrap */
            uint64_t end = addr + len;
            bool intersect = !(event_addr >= end || addr >= event_end);
            return intersect;
        }, forward);
    }

    EventHandle filter_type(EventHandle start, int type, bool forward) {
        return filter(start, [=](EventHandle h) {
            return handle_to_event(h)->event_type() == type;
        }, forward);
    }

    State replay_from_state_until(const State &initial_state, EventHandle until) {
        State state(initial_state);

        while (!event_handle_invalid(state.ev)) {
            // Apply event effects up to but not including stop event
            if (state.ev >= until) break;

            auto rev = handle_to_event(state.ev);
            if (rev->event_type() == EventUnion_memoryEvent) {
                auto mev = rev->event_as_memoryEvent();
                if (mev->isStore()) {
                    const uint8_t *bytes;
                    uint64_t sz;
                    uint64_t v;

                    if (mev->data()) {
                        sz = mev->data()->size();
                        bytes = mev->data()->data();
                    } else {
                        v = mev->value();
                        sz = 1 << mev->size();
                        assert(sz <= 8);
                        bytes = (uint8_t*)&v; // XXX: Portability
                    }

                    for (size_t i = 0; i < sz; i++) {
                        state.mem[mev->addr() + i] = bytes[i];
                    }
                }
            }

            state.ev = get_next_event(state.ev);
        }

        return state;
    }

    State replay_until(EventHandle until) {
        State state;
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
        .def_readonly("mem", &State::mem)
        .def("__getitem__", [](const State &self, size_t i) { return self.mem.at(i); })
        .def("__copy__",  [](const State &self) { return State(self); })
        ;

    py::class_<NativeTraceManager>(m, "NativeTraceManager")
        .def(py::init<int, int>())
        .def("event_handle_invalid", &NativeTraceManager::event_handle_invalid)
        .def("get_first_event", &NativeTraceManager::get_first_event)
        .def("get_last_event", &NativeTraceManager::get_last_event)
        .def("get_prev_event", &NativeTraceManager::get_prev_event)
        .def("get_next_event", &NativeTraceManager::get_next_event)
        .def("get_num_events", &NativeTraceManager::get_num_events)
        .def("replay", &NativeTraceManager::replay)
        .def("replay_from_state_until", &NativeTraceManager::replay_from_state_until)
        .def("replay_until", &NativeTraceManager::replay_until)
        .def("filter_type", &NativeTraceManager::filter_type)
        .def("filter_exec_addr", &NativeTraceManager::filter_exec_addr)
        .def("filter_memory", &NativeTraceManager::filter_memory)
        ;

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}