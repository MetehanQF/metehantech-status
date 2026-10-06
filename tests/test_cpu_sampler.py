import importlib.util
import json
import math
import threading
import time
from pathlib import Path

import pytest

import cpu_sampler

ROOT = Path(__file__).resolve().parents[1]


def load_pcold_agent():
    spec = importlib.util.spec_from_file_location("pcold_agent", ROOT / "pcold_metrics" / "metehantech-metrics.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # __main__ guard: no server is started
    return module


PCOLD = load_pcold_agent()
IMPLEMENTATIONS = [cpu_sampler.CpuSampler, PCOLD.CpuSampler]


class Counters:
    """Synthetic /proc/stat: advance by (busy, idle) jiffies per step."""

    def __init__(self):
        self.idle = 1_000_000
        self.total = 2_000_000
        self.error = None

    def advance(self, busy, idle):
        self.idle += idle
        self.total += busy + idle

    def __call__(self):
        if self.error is not None:
            raise self.error
        return self.idle, self.total


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make(impl):
    counters, clock = Counters(), Clock()
    return impl(read_counters=counters, clock=clock), counters, clock


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
def test_first_sample_is_warmup_not_zero(impl):
    sampler, counters, clock = make(impl)
    assert sampler.sample() is None
    clock.now += 10
    counters.advance(0, 1000)
    assert sampler.sample() is None  # window still shorter than MIN_WINDOW


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
def test_second_sample_after_interval_is_valid_interval_average(impl):
    sampler, counters, clock = make(impl)
    sampler.sample()
    clock.now += 60
    counters.advance(busy=2_400, idle=9_600)  # 20 % over the whole minute
    assert sampler.sample() == 20.0


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
@pytest.mark.parametrize(("busy", "idle", "expected"), [(0, 12_000, 0.0), (6_000, 6_000, 50.0), (12_000, 0, 100.0), (11_988, 12, 99.9)])
def test_zero_normal_and_high_utilization(impl, busy, idle, expected):
    sampler, counters, clock = make(impl)
    sampler.sample()
    clock.now += 60
    counters.advance(busy, idle)
    value = sampler.sample()
    assert value == expected
    assert value is not None and math.isfinite(value) and 0.0 <= value <= 100.0


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
def test_short_spike_is_averaged_over_window(impl):
    sampler, counters, clock = make(impl)
    sampler.sample()
    # 0.3 s of 100 % inside an otherwise idle minute (4 cores x 100 Hz).
    clock.now += 60
    counters.advance(busy=120, idle=23_880)
    assert sampler.sample() == 0.5


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
def test_frequent_callers_use_window_at_least_min_window(impl):
    sampler, counters, clock = make(impl)
    sampler.sample()
    for _ in range(12):  # every 5 s for a minute, 25 % busy
        clock.now += 5
        counters.advance(busy=500, idle=1_500)
        value = sampler.sample()
    assert value == 25.0
    # A burst of extra calls must not shrink the window below MIN_WINDOW.
    for _ in range(50):
        clock.now += 0.01
        assert sampler.sample() == 25.0


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
def test_long_gap_restarts_warmup(impl):
    sampler, counters, clock = make(impl)
    sampler.sample()
    clock.now += 3600
    counters.advance(1000, 1000)
    assert sampler.sample() is None
    clock.now += 60
    counters.advance(300, 2700)
    assert sampler.sample() == 10.0


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
def test_counter_reset_and_read_errors_are_unavailable(impl):
    sampler, counters, clock = make(impl)
    sampler.sample()
    clock.now += 60
    counters.total -= 10_000  # reboot/reset
    assert sampler.sample() is None
    counters.error = OSError("proc unavailable")
    clock.now += 60
    assert sampler.sample() is None
    counters.error = ValueError("bad format")
    assert sampler.sample() is None


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
def test_restart_starts_warmup_again(impl):
    sampler, counters, clock = make(impl)
    sampler.sample()
    clock.now += 60
    counters.advance(100, 900)
    assert sampler.sample() == 10.0
    restarted = impl(read_counters=counters, clock=clock)
    assert restarted.sample() is None


@pytest.mark.parametrize("impl", IMPLEMENTATIONS)
def test_concurrent_calls_are_consistent_and_non_blocking(impl):
    sampler, counters, clock = make(impl)
    sampler.sample()
    clock.now += 60
    counters.advance(3_000, 9_000)
    results, started = [], time.monotonic()

    def call():
        results.append(sampler.sample())

    threads = [threading.Thread(target=call) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert set(results) == {25.0}
    assert time.monotonic() - started < 0.5


@pytest.mark.parametrize("module", [cpu_sampler, PCOLD])
def test_proc_stat_parser_excludes_guest_and_counts_iowait_idle(tmp_path, module):
    stat = tmp_path / "stat"
    stat.write_text("cpu  100 10 50 800 40 5 5 0 70 7\ncpu0 1 1 1 1 1 1 1 1 1 1\n")
    idle, total = module.read_proc_stat(str(stat))
    assert idle == 840
    assert total == 1010  # guest (70) and guest_nice (7) excluded
    stat.write_text("intr 1 2 3\n")
    with pytest.raises(ValueError):
        module.read_proc_stat(str(stat))


def test_real_proc_stat_is_readable_without_blocking():
    started = time.monotonic()
    idle, total = cpu_sampler.read_proc_stat()
    assert 0 < idle < total
    assert time.monotonic() - started < 0.05


def test_status_app_reports_unknown_during_warmup_and_percent_after(monkeypatch):
    import app

    counters, clock = Counters(), Clock()
    monkeypatch.setattr(app, "_CPU_SAMPLER", cpu_sampler.CpuSampler(read_counters=counters, clock=clock))
    assert app.read_cpu_percent() == "UNKNOWN"
    clock.now += 60
    counters.advance(600, 5_400)
    assert app.read_cpu_percent() == "10.0%"
    clock.now += 60
    counters.advance(0, 6_000)
    assert app.read_cpu_percent() == "0.0%"


def test_status_app_cpu_never_sleeps(monkeypatch):
    import app

    monkeypatch.setattr(time, "sleep", lambda *_: (_ for _ in ()).throw(AssertionError("sleep called")))
    started = time.monotonic()
    for _ in range(20):
        app.read_cpu_percent()
    assert time.monotonic() - started < 0.2


def test_status_app_source_exception_is_unknown(monkeypatch):
    import app

    class Broken:
        def sample(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(app, "_CPU_SAMPLER", Broken())
    assert app.read_cpu_percent() == "UNKNOWN"


def test_pcold_agent_http_contract_unchanged_and_null_during_warmup(monkeypatch):
    counters, clock = Counters(), Clock()
    monkeypatch.setattr(PCOLD, "CPU_SAMPLER", PCOLD.CpuSampler(read_counters=counters, clock=clock))
    monkeypatch.setattr(PCOLD, "service_status", lambda service: "OK")
    monkeypatch.setattr(PCOLD, "smart_status", lambda: "OK")

    class Handler(PCOLD.MetricsHandler):
        def __init__(self):
            self.path = "/status"
            self.sent = []
            import io
            self.wfile = io.BytesIO()

        def send_response(self, code):
            self.sent.append(code)

        def send_header(self, *args):
            pass

        def end_headers(self):
            pass

    first = Handler()
    first.do_GET()
    body = json.loads(first.wfile.getvalue())
    assert set(body) == {"hostname", "online", "temperature", "ram", "disk", "load", "cpu", "uptime", "docker", "smart"}
    assert body["cpu"] is None
    clock.now += 60
    counters.advance(150, 2_850)
    second = Handler()
    second.do_GET()
    assert json.loads(second.wfile.getvalue())["cpu"] == 5.0


def test_pi_status_maps_pcold_null_cpu_to_unknown_not_zero():
    import app

    assert app.old_pc_metric(None, "%") == "UNKNOWN"
    assert app.old_pc_metric(0.0, "%") == "0%"
    assert app.old_pc_metric(float("nan"), "%") == "UNKNOWN"
