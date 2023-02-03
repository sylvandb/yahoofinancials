from os import environ
import random
import requests
from time import sleep, time

# meh
VERSTR = '1.3'


# log information about failed requests - get or parse failures
LOG_FAILURES = True

# see urls with delays
SEE_FETCH = False



# print how much debug output
# can be changed later using set_debug(n)
DEBUG = 0
try:
    DEBUG = int(environ['debug_yahoofinancials'])
except (KeyError, TypeError):
    pass

# report various elapsed time
TIME_REPORT = False
try:
    TIME_REPORT = bool(int(environ['time_yahoofinancials']))
except (KeyError, TypeError):
    pass
try:
    STAT_REPORT = int(environ['stat_yahoofinancials'])
except (KeyError, TypeError):
    STAT_REPORT = TIME_REPORT


def _time_report(f, *a, **kwa):
    bef = time()
    rv = f(*a, **kwa)
    elapsed = time() - bef
    if TIME_REPORT: print(f"\nto {f}: {elapsed}", file=sys.stderr, end='')
    return rv


def _debug():
    return DEBUG

def _trace(*a, **ka):
    trace(*a, **ka)

def set_debug(n=None):
    global DEBUG, trace
    if n is not None:
        print(f'set_debug({n})')
        DEBUG = int(n)
    if DEBUG:
        import inspect
        import traceback

        _tracefargs = []
        def trace(*args):
            fname = traceback.extract_stack(None, 2)[0][2]
            fargnames, _, _, flocals = inspect.getargvalues(inspect.currentframe().f_back)
            fargs = ['%s=%s' % (a, flocals[a]) for a in fargnames]
            if fargs == _tracefargs:
                fargs = ['...']
            else:
                del _tracefargs[:]
                _tracefargs.extend(fargs)
            if DEBUG > 9:
                print("%s(%r)\n :  %s" % (
                    fname,
                    ', '.join(fargs),
                    '\n :  '.join(args),
                    ), file=sys.stderr)
            elif DEBUG > 1:
                print("%s(%r)" % (
                    fname,
                    ', '.join(fargs),
                    ), file=sys.stderr)
            else:
                print("%s(...x%d...)" % (
                    fname,
                    len(fargs),
                    ), file=sys.stderr)
        if DEBUG > 5: SEE_FETCH = True
    else:
        def trace(*args): pass



def reset_headers():
    HEADERS.clear()
    # add user-agent header
    # add Accept-Encoding header for gzip (and deflate)
    # yahoo will sometimes send gzip even without the header!
    HEADERS.update({
        'User-Agent': "%s %s" % (random.choice(UAs), VERSTR),
        'Accept-Encoding': 'gzip, deflate',
    })

# user-agent header options
# yahoo will sometimes start returning 404 for some user-agents
# yahoo will sometimes be too smart for some user-agents
UAs = [
    'My User Agent',
    'World Wide Web',
]

HEADERS = {}


# timeout objectives:
#  - fail fast if it is going to fail eventually
#  - don't fail if it just needs a second or two longer to succeed
# with timeout=5:
#  Max fetch 5.1632, last: 0.6376, average(0.5085 .. 5.1632, 80): 1.5045
#   6: **********
#   7: ***************************
#   8: **********
#   9: *******
#  16: *
#  23: **
#  28: **
#  29: ****
#  30: ****
#  32: ***
#  33: ***
#  36: *
#  41: **
#  44: **
#  45: *
#  52: *
# conclusions:
#  -seems 2s are plenty when things are normal, but not enough on busy days
#  -tried timeout values: 5, 10, 20s; with no repeatable difference in failures
#  -less than 5 seems potentially a problem, but maybe only if breaking anyway?
#  -timeout is not always respected - timeout 6 has succeeded after 18 seconds
READ_TIMEOUT = 6
READ_TRIES = 2

# Minimum interval between Yahoo Finance requests for this instance
_MIN_INTERVAL = 7
_MAX_INTERVAL = 30
# on error a longer interval
_MORE_INTERVAL = 1.1
# on success a shorter interval
_LESS_INTERVAL = 0.96
# Always delay a minimum - like a human
_MIN_DELAY = 0.25
# vary by +/-
_VARIANCE = 2

# track the last get timestamp to add a minimum delay between gets - be nice!
_interval = _MIN_INTERVAL
_lastget = 0
def _be_nice(activitycb):
    global _lastget
    now = time()
    if _lastget:
        elapsed = now - _lastget
        this_delay = round(_interval - elapsed - _VARIANCE + (random.random() * 2 * _VARIANCE), 2)
        this_delay = max(_MIN_DELAY, this_delay)
        if TIME_REPORT: print(f"\n{now:.3f} elapsed: {elapsed:.3f}, delay: {this_delay:.3f}", file=sys.stderr, end='')
        if SEE_FETCH:   print(f"\n{now:.3f} elapsed: {elapsed:.3f}, delay: {this_delay:.3f}")
        now += this_delay
        while (now - time()) > 1.5:
            sleep(1.1)
            activitycb(0)
        sleep(max(0, now - time()))
    _lastget = now
    activitycb(0)


# this cache holds data from urls
# cached data is used when one in a group fails
# otherwise usually the self._cache in the class - it's alread parsed
_url_cache = {}
_fstats = {
    'pass': {
        'num': 0,
        'sum': 0,
        'avg': 0,
        'min': 99,
        'max': 0,
        'hist': {}
    },
    'fail': {
        'num': 0,
        'sum': 0,
        'avg': 0,
        'min': 99,
        'max': 0,
        'hist': {}
    },
    'cached': 0,
    'timeout': READ_TIMEOUT,
}

def fetch_stats():
    return _fstats

def fetch_stats_hist_as_str(fs=_fstats['pass']):
    histo = []
    num = _fstats['pass']['num']
    err = _fstats['fail']['num']
    cached = _fstats['cached']
    if num or err or cached:
        histo.extend("%2s: %s" % (k, '*' * fs['hist'][k]) for k in sorted(fs['hist'].keys()))
        histo.append(f"number: {num}, errors: {err}, cached: {cached}")
    return histo


_fetch_start = []

def _fetch_stats_update(fs, elapsed):
    fs['num'] += 1
    fs['sum'] += elapsed
    fs['avg'] = fs['sum'] / fs['num']
    fs['min'] = min(fs['min'], elapsed)
    fs['max'] = max(fs['max'], elapsed)
    # primitive 'ceiling' -- 0.0-0.1 = 1, 0.101-0.2 = 2, ...
    histn = int(-(elapsed * 100000 // -10000))
    fs['hist'][histn] = 1 + fs['hist'].get(histn, 0)

# maybe this should be a context manager
def _fetch_stats(start=False, err=None, url=None, cached=False):
    global _interval
    if cached:
        _fstats['cached'] += 1
    elif err:
        elapsed = time() - _fetch_start.pop()
        _fetch_stats_update(_fstats['fail'], elapsed)
        # increase delay between attempts
        _interval = min(_interval * _MORE_INTERVAL, _MAX_INTERVAL)
        print('\nError req.get(%r, %r): %s\nmin_interval now %f' % (url, HEADERS['User-Agent'], err, _interval), file=sys.stderr)
        # try different headers - specifically user-agent
        reset_headers()
    elif start and _fetch_start:
        raise ValueError("_fetch_stats request overlap is not supported: %s" % (url,))
    elif start:
        _fetch_start.append(time())
    else:
        elapsed = time() - _fetch_start.pop()
        fsp = _fstats['pass']
        if elapsed < fsp['avg']:
            # decrease delay between attempts
            _interval = max(_interval * _LESS_INTERVAL, _MIN_INTERVAL)
        #elif elapsed > (2 * fsp['avg']):
        #    # increase delay between attempts
        #    _interval = min(_interval * _MORE_INTERVAL, _MAX_INTERVAL)
        _fetch_stats_update(fsp, elapsed)
        if STAT_REPORT and not fsp['num'] % 10:
            fsf = _fstats['fail']
            outfile = sys.stdout if STAT_REPORT > 1 else sys.stderr
            report = [f"\nMax fetch {fsp['max']:.4f}, last: {elapsed:.4f}, average: {fsp['avg']:.4f}, ok: {fsp['num']} ({fsp['min']:.4f} .. {fsp['max']:.4f}), errors: {fsf['num']}"]
            if fsf['num']:
                report.append(f"({fsf['min']:.4f} .. {fsf['max']:.4f}, average: {fsf['avg']})")
            print(' '.join(report), file=outfile)
            print('\n'.join(fetch_stats_hist_as_str()), file=outfile)


def _fetch_url(url, activitycb):
    trace()
    try:
        r = _url_cache[url]
        _fetch_stats(cached=True)
        activitycb()
        return r
    except KeyError:
        pass
    _be_nice(activitycb)
    if SEE_FETCH: print(f"  _fetch_url({url})")
    _fetch_stats(start=True)
    try:
        r = _time_report(requests.get, url, headers=HEADERS, timeout=READ_TIMEOUT)
    except (requests.Timeout, requests.HTTPError) as e:
        _fetch_stats(url=url, err=str(e))
        raise
    # cache everything except temporary fails
    if r.status_code < 500:
        _fetch_stats()
        _url_cache[url] = (r.status_code, r.text)
    else:
        _fetch_stats(url=url, err='HTTP_%s' % (r.status_code,))
    activitycb()
    return r.status_code, r.text



set_debug()
reset_headers()
