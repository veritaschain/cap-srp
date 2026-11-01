"""Deterministic ordering checks, including a frozen/reversed clock."""

from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import os
import threading
import uuid

import pytest

from cap_srp.core import events


@pytest.fixture(autouse=True)
def isolated_generator(monkeypatch):
    monkeypatch.setattr(events, "_uuid_lock", threading.Lock())
    monkeypatch.setattr(events, "_uuid_timestamp_ms", -1)
    monkeypatch.setattr(events, "_uuid_random", 0)


def test_frozen_clock_preserves_generation_order_and_uuid_layout(monkeypatch):
    timestamp = 1_793_491_200_123
    monkeypatch.setattr(events.time, "time_ns", lambda: timestamp * 1_000_000)
    ids = [events.generate_event_id() for _ in range(2000)]
    assert ids == sorted(set(ids))
    parsed = [uuid.UUID(value) for value in ids]
    assert all(value.version == 7 and value.variant == uuid.RFC_4122 for value in parsed)
    assert all(value.int >> 80 == timestamp for value in parsed)


def test_clock_rollback_reuses_previous_tick_until_clock_advances(monkeypatch):
    timestamps = iter([1234, 1233, 1234, 1235])
    monkeypatch.setattr(events.time, "time_ns", lambda: next(timestamps) * 1_000_000)
    randoms = iter([100, 0])
    monkeypatch.setattr(events.secrets, "randbits", lambda bits: next(randoms))
    ids = [events.generate_event_id() for _ in range(4)]
    assert ids == sorted(set(ids))
    assert [uuid.UUID(value).int >> 80 for value in ids] == [1234, 1234, 1234, 1235]


def test_concurrent_calls_at_one_tick_are_unique_and_ordered_per_thread(monkeypatch):
    monkeypatch.setattr(events.time, "time_ns", lambda: 1_234_000_000)
    barrier = threading.Barrier(8)

    def generate_batch(_):
        barrier.wait()
        return [events.generate_event_id() for _ in range(250)]

    with ThreadPoolExecutor(max_workers=8) as pool:
        batches = list(pool.map(generate_batch, range(8)))
    assert all(batch == sorted(batch) for batch in batches)
    assert len({value for batch in batches for value in batch}) == 2000


def test_counter_exhaustion_never_wraps_and_recovers_after_clock_advance(monkeypatch):
    monkeypatch.setattr(events.time, "time_ns", lambda: 1_234_000_000)
    randoms = iter([(1 << 74) - 1, 0])
    monkeypatch.setattr(events.secrets, "randbits", lambda bits: next(randoms))
    last = events.generate_event_id()
    with pytest.raises(OverflowError):
        events.generate_event_id()
    with pytest.raises(OverflowError):
        events.generate_event_id()
    monkeypatch.setattr(events.time, "time_ns", lambda: 1_235_000_000)
    assert events.generate_event_id() > last


@pytest.mark.parametrize("timestamp", [-1, 1 << 48])
def test_out_of_range_clock_rejected_without_wrapping(monkeypatch, timestamp):
    monkeypatch.setattr(events.time, "time_ns", lambda: timestamp * 1_000_000)
    with pytest.raises(ValueError, match="timestamp range"):
        events.generate_event_id()


def _child_generate(connection):
    connection.send((os.getpid(), events.generate_event_id()))
    connection.close()


@pytest.mark.skipif("fork" not in multiprocessing.get_all_start_methods(), reason="POSIX fork only")
def test_child_reinitializes_inherited_locked_state(monkeypatch):
    monkeypatch.setattr(events.time, "time_ns", lambda: 1_234_000_000)
    monkeypatch.setattr(events.secrets, "randbits", lambda bits: os.getpid() << 20)
    parent_id = events.generate_event_id()
    context = multiprocessing.get_context("fork")
    reader, writer = context.Pipe(duplex=False)
    process = context.Process(target=_child_generate, args=(writer,))
    # A fork during another thread's generation must not leave the child stuck.
    events._uuid_lock.acquire()
    try:
        process.start()
    finally:
        events._uuid_lock.release()
        writer.close()
    try:
        assert reader.poll(5), "child inherited the parent's locked UUID mutex"
        child_pid, child_id = reader.recv()
        assert child_id != parent_id
        value = uuid.UUID(child_id).int
        random_bits = (((value >> 64) & 0xFFF) << 62) | (value & ((1 << 62) - 1))
        assert random_bits == child_pid << 20
        process.join(timeout=5)
        assert process.exitcode == 0
    finally:
        reader.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
