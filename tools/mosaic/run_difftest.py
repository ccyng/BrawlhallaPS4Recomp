import argparse
import collections
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

def default_exe():
    for p in (os.path.join(HERE, '..', '..', 'OrbisGlue.exe'), os.path.join(HERE, '..', '..', 'build', 'shadps4.exe')):
        if os.path.exists(p):
            return os.path.abspath(p)
    return 'OrbisGlue.exe'

def read_progress(path):
    try:
        with open(path, encoding='ascii', errors='replace') as f:
            return f.read().split()
    except OSError:
        return []

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out')
    ap.add_argument('eboot')
    ap.add_argument('--dll', default='mosaic.dll')
    ap.add_argument('--exe', default=default_exe(), help='OrbisGlue.exe (or shadps4.exe of this tree)')
    ap.add_argument('--stall', type=float, default=20.0, help='seconds on one function = stuck')
    ap.add_argument('--boot', type=float, default=120.0, help='seconds allowed to reach the test')
    ap.add_argument('--resume', action='store_true', help='continue after the last logged function')
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    log_path = os.path.join(out, 'mosaic_difftest.log')
    prog_path = os.path.join(out, 'mosaic_progress.txt')
    dll = os.path.join(out, args.dll)
    start = 0
    if args.resume and os.path.exists(prog_path):
        p = read_progress(prog_path)
        if p and p[0].isdigit():
            start = int(p[0]) + 1
    elif os.path.exists(log_path):
        os.remove(log_path)

    t0 = time.time()
    restarts = 0
    while True:
        if os.path.exists(prog_path):
            os.remove(prog_path)
        env = dict(os.environ, MOSAIC_FROM=str(start))
        with open(os.path.join(out, 'difftest_stdout.txt'), 'a', encoding='utf-8') as so:
            so.write(f'\n=== run from {start} ===\n')
            so.flush()
            proc = subprocess.Popen([args.exe, '--orbisglue-difftest', dll, '-g', args.eboot],
                                    cwd=out, env=env, stdout=so, stderr=subprocess.STDOUT)
            last, since, booted = None, time.time(), False
            while proc.poll() is None:
                time.sleep(1.0)
                p = read_progress(prog_path)
                if p != last:
                    last, since = p, time.time()
                    booted = booted or bool(p)
                limit = args.stall if booted else args.boot
                if time.time() - since > limit:
                    proc.kill()
                    proc.wait()
                    break
        p = read_progress(prog_path)
        if p and p[0] == 'DONE':
            break
        if not p or not p[0].isdigit():
            print(f'[driver] run from {start} died before testing anything (exit {proc.returncode})')
            sys.exit(2)
        idx, addr = int(p[0]), p[1]
        kind = 'HANG' if proc.returncode is not None and time.time() - since > args.stall else 'CRASH'
        with open(log_path, 'a', encoding='ascii') as lf:
            lf.write(f'{kind} {addr} exit={proc.returncode}\n')
        restarts += 1
        print(f'[driver] {kind} at #{idx} {addr} (exit {proc.returncode}); '
              f'restart {restarts} from #{idx + 1}, {time.time() - t0:.0f} s', flush=True)
        start = idx + 1

    counts = collections.Counter()
    with open(log_path, encoding='ascii', errors='replace') as lf:
        for line in lf:
            if line.strip():
                counts[line.split()[0]] += 1
    total = sum(counts.values())
    print(f'[driver] done in {time.time() - t0:.0f} s, {restarts} restarts: ' +
          ', '.join(f'{k} {v}' for k, v in counts.most_common()) + f' (of {total})')

if __name__ == '__main__':
    main()
