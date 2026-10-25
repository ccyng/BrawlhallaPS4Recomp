import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_difftest import default_exe

def step(title, cmd):
    print(f'\n=== {title}\n    {" ".join(cmd)}', flush=True)
    t0 = time.time()
    r = subprocess.run(cmd)
    print(f'=== {title}: {"ok" if r.returncode == 0 else "FAILED"} in {time.time() - t0:.0f} s', flush=True)
    if r.returncode:
        sys.exit(r.returncode)

def main():
    ap = argparse.ArgumentParser(description='Lift a PS4 game to C and build it (OrbisGlue Mosaic).')
    ap.add_argument('game', help='the dumped game folder (with eboot.bin) or eboot.bin itself')
    ap.add_argument('--out', help='where the C and mosaic.dll (.so on Linux) go (default: <game>/_mosaic)')
    ap.add_argument('--jobs', type=int, default=6, help='compilers at once (default 6)')
    ap.add_argument('--switchable', action='store_true',
                    help='every lifted function can be sent back to the original (MOSAIC_OFF=...)')
    ap.add_argument('--difftest', action='store_true', help='prove the lifted functions (long)')
    ap.add_argument('--play', action='store_true', help='start the game on the lifted code')
    ap.add_argument('--exe', default=default_exe(), help='OrbisGlue.exe')
    a = ap.parse_args()

    try:
        import capstone
    except ImportError:
        sys.exit('capstone is missing: pip install capstone')

    eboot = os.path.abspath(a.game)
    if os.path.isdir(eboot):
        eboot = os.path.join(eboot, 'eboot.bin')
    if not os.path.isfile(eboot):
        sys.exit(f'no eboot.bin at {eboot}')
    out = os.path.abspath(a.out or os.path.join(os.path.dirname(eboot), '_mosaic'))
    os.makedirs(out, exist_ok=True)
    dll = os.path.join(out, 'mosaic.dll' if os.name == 'nt' else 'mosaic.so')

    lift = [sys.executable, os.path.join(HERE, 'lift64.py'), eboot, out]
    if a.switchable:
        lift.append('--switchable')
    step('lift (x86-64 -> C)', lift)
    step('build (C -> mosaic.dll)', [sys.executable, os.path.join(HERE, 'build_mosaic.py'), out, dll,
                                    '--jobs', str(a.jobs)])
    if a.difftest:
        step('difftest (lifted vs original)', [sys.executable, os.path.join(HERE, 'run_difftest.py'), out,
                                               eboot, '--exe', a.exe])
    play = [a.exe, '--orbisglue-mosaic', dll, '-g', eboot]
    print(f'\nDone. To play on the lifted code:\n    "{a.exe}" --orbisglue-mosaic "{dll}" -g "{eboot}"')
    if a.play:
        subprocess.Popen(play, cwd=os.path.dirname(a.exe) or None)

if __name__ == '__main__':
    main()
