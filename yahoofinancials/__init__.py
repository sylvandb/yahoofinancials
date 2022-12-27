#!/usr/bin/env python3
"""
==============================
The Yahoo Financials Module
==============================

Author: Connor Sanders
Changed: Sylvan Butler
Python3 only

Copyright (c) 2019 Connor Sanders
Copyright (c) 2021 Sylvan Butler
MIT License

List of Included Functions:

1) get_financial_stmts(frequency, statement_type, reformat=True)
   - frequency can be either 'annual' or 'quarterly'.
   - statement_type can be 'income', 'balance', 'cash'.
   - reformat optional value defaulted to true. Enter False for unprocessed raw data from Yahoo Finance.
2) get_stock_price_data(reformat=True)
   - reformat optional value defaulted to true. Enter False for unprocessed raw data from Yahoo Finance.
3) get_stock_earnings_data(reformat=True)
   - reformat optional value defaulted to true. Enter False for unprocessed raw data from Yahoo Finance.
4) get_summary_data(reformat=True)
   - reformat optional value defaulted to true. Enter False for unprocessed raw data from Yahoo Finance.
5) get_stock_quote_type_data()
6) get_historical_price_data(start_date, end_date, time_interval)
   - Gets historical price data for currencies, stocks, indexes, cryptocurrencies, and commodity futures.
   - start_date should be entered in the 'YYYY-MM-DD' format. First day that financial data will be pulled.
   - end_date should be entered in the 'YYYY-MM-DD' format. Last day that financial data will be pulled.
   - time_interval can be either 'daily', 'weekly', or 'monthly'. Parameter determines the time period interval.

Usage Examples:
from yahoofinancials import YahooFinancials
#tickers = 'AAPL'
#or
tickers = ['AAPL', 'WFC', 'F', 'JPY=X', 'XRP-USD', 'GC=F']
yahoo_financials = YahooFinancials(tickers)
balance_sheet_data = yahoo_financials.get_financial_stmts('quarterly', 'balance')
earnings_data = yahoo_financials.get_stock_earnings_data()
historical_prices = yahoo_financials.get_historical_price_data('2015-01-15', '2017-10-15', 'weekly')
"""

import os
import sys
import calendar
import re
from json import loads
import time
from bs4 import BeautifulSoup
import datetime
import pytz
import random
from subprocess import check_output, CalledProcessError
import requests
from gzip import decompress as gzipdecompress
from zlib import decompress as zlibdecompress

# encrypted responses 20221221
import hashlib
from base64 import b64decode
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
except ImportError:
    # Cryptodome installed by another name
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

# meh
VERSTR = '1.2'

# log information about failed requests - get or parse failures
LOG_FAILURES = True

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

# report various elapsed time
TIME_REPORT = False
try:
    TIME_REPORT = bool(int(os.environ['time_yahoofinancials']))
except (KeyError, TypeError):
    pass
try:
    STAT_REPORT = int(os.environ['stat_yahoofinancials'])
except (KeyError, TypeError):
    STAT_REPORT = TIME_REPORT
# see urls with delays
SEE_FETCH = False

# print how much debug output
DEBUG = 0
try:
    DEBUG = int(os.environ['debug_yahoofinancials'])
except (KeyError, TypeError):
    pass

# user-agent header options
# yahoo will sometimes start returning 404 for some user-agents
# yahoo will sometimes be too smart for some user-agents
UAs = [
    'My User Agent',
    'World Wide Web',
]

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
    now = time.time()
    if _lastget:
        elapsed = now - _lastget
        this_delay = round(_interval - elapsed - _VARIANCE + (random.random() * 2 * _VARIANCE), 2)
        this_delay = max(_MIN_DELAY, this_delay)
        if TIME_REPORT: print(f"\n{now:.3f} elapsed: {elapsed:.3f}, delay: {this_delay:.3f}", file=sys.stderr, end='')
        if SEE_FETCH:   print(f"\n{now:.3f} elapsed: {elapsed:.3f}, delay: {this_delay:.3f}")
        now += this_delay
        while (now - time.time()) > 1.5:
            time.sleep(1.1)
            activitycb(0)
        time.sleep(max(0, now - time.time()))
    _lastget = now
    activitycb(0)


# decrypt encrypted responses 20221221
# from https://github.com/ranaroussi/yfinance/issues/1246#issuecomment-1356709536
def _decrypt(data):

    def EVPKDF(
        password,
        salt,
        keySize=32,
        ivSize=16,
        iterations=1,
        hashAlgorithm="md5",
    ) -> tuple:
        """OpenSSL EVP Key Derivation Function
        Args:
            password (Union[str, bytes, bytearray]): Password to generate key from.
            salt (Union[bytes, bytearray]): Salt to use.
            keySize (int, optional): Output key length in bytes. Defaults to 32.
            ivSize (int, optional): Output Initialization Vector (IV) length in bytes. Defaults to 16.
            iterations (int, optional): Number of iterations to perform. Defaults to 1.
            hashAlgorithm (str, optional): Hash algorithm to use for the KDF. Defaults to 'md5'.
        Returns:
            key, iv: Derived key and Initialization Vector (IV) bytes.
        Taken from: https://gist.github.com/rafiibrahim8/0cd0f8c46896cafef6486cb1a50a16d3
        OpenSSL original code: https://github.com/openssl/openssl/blob/master/crypto/evp/evp_key.c#L78
        """
        assert iterations > 0, "Iterations can not be less than 1."
        if isinstance(password, str):
            password = password.encode("utf-8")
        final_length = keySize + ivSize
        key_iv = b""
        block = None
        while len(key_iv) < final_length:
            hasher = hashlib.new(hashAlgorithm)
            if block:
                hasher.update(block)
            hasher.update(password)
            hasher.update(salt)
            block = hasher.digest()
            for _ in range(1, iterations):
                block = hashlib.new(hashAlgorithm, block).digest()
            key_iv += block
        key, iv = key_iv[:keySize], key_iv[keySize:final_length]
        return key, iv

    encrypted = b64decode(data['context']['dispatcher']['stores'])
    assert encrypted[:8] == b"Salted__"
    salt = encrypted[8:16]
    encrypted = encrypted[16:]

    _cs = data["_cs"]
    _crdata = loads(data["_cr"])
    _crwords = _crdata["words"]
    _cr = b"".join(int.to_bytes(i, length=4, byteorder="big", signed=True) for i in _crwords)
    assert _crdata["sigBytes"] == len(_cr)

    password = hashlib.pbkdf2_hmac("sha1", _cs.encode("utf8"), _cr, 1, dklen=32).hex()
    key, iv = EVPKDF(password, salt, keySize=32, ivSize=16, iterations=1, hashAlgorithm="md5")
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    plaintext = cipher.decrypt(encrypted)
    plaintext = unpad(plaintext, 16, style="pkcs7")
    return loads(plaintext)


def time_report(f, *a, **kwa):
    bef = time.time()
    rv = f(*a, **kwa)
    elapsed = time.time() - bef
    if TIME_REPORT: print(f"\nto {f}: {elapsed}", file=sys.stderr, end='')
    return rv


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
set_debug()


def reset_headers():
    HEADERS.clear()
    # add user-agent header
    # add Accept-Encoding header for gzip (and deflate)
    # yahoo will sometimes send gzip even without the header!
    HEADERS.update({
        'User-Agent': "%s %s" % (random.choice(UAs), VERSTR),
        'Accept-Encoding': 'gzip, deflate',
    })

HEADERS = {}
reset_headers()


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
        elapsed = time.time() - _fetch_start.pop()
        _fetch_stats_update(_fstats['fail'], elapsed)
        # increase delay between attempts
        _interval = min(_interval * _MORE_INTERVAL, _MAX_INTERVAL)
        print('\nError req.get(%r, %r): %s\nmin_interval now %f' % (url, HEADERS['User-Agent'], err, _interval), file=sys.stderr)
        # try different headers - specifically user-agent
        reset_headers()
    elif start and _fetch_start:
        raise ValueError("_fetch_stats request overlap is not supported: %s" % (url,))
    elif start:
        _fetch_start.append(time.time())
    else:
        elapsed = time.time() - _fetch_start.pop()
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

def fetch_url(url, activitycb):
    trace()
    try:
        r = _url_cache[url]
        _fetch_stats(cached=True)
        activitycb()
        return r
    except KeyError:
        pass
    _be_nice(activitycb)
    if SEE_FETCH: print(f"  fetch_url({url})")
    _fetch_stats(start=True)
    try:
        r = time_report(requests.get, url, headers=HEADERS, timeout=READ_TIMEOUT)
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


# Custom Exception class to handle custom error
class ManagedException(Exception):
    data = None

class ParseException(ManagedException):
    pass

class URLOpenException(ManagedException):
    pass


# Class containing Yahoo Finance ETL Functionality
class YahooFinanceETL(object):

    def __init__(self, ticker, activity_callback=None):
        self.ticker = [ticker.upper()] if isinstance(ticker, str) else [t.upper() for t in ticker]
        self.activitycb = activity_callback or (lambda x=None: None)
        self._cache = {}

    # Meta-data dictionaries for the classes to use
    YAHOO_FINANCIAL_TYPES = {
        'income': ['financials', 'incomeStatementHistory', 'incomeStatementHistoryQuarterly'],
        'balance': ['balance-sheet', 'balanceSheetHistory', 'balanceSheetHistoryQuarterly', 'balanceSheetStatements'],
        'cash': ['cash-flow', 'cashflowStatementHistory', 'cashflowStatementHistoryQuarterly', 'cashflowStatements'],
        'keystats': ['key-statistics'],
        'history': ['history'],
        'profile': ['profile'],
    }

    # Interval value translation dictionary
    _INTERVAL_DICT = {
        'daily': '1d',
        'weekly': '1wk',
        'monthly': '1mo'
    }

    # Base Yahoo Finance URL for the class to build on
    _BASE_YAHOO_URL = 'https://finance.yahoo.com/quote/'

    # Public static method to format date serial string to readable format and vice versa
    @staticmethod
    def format_date(in_date):
        if isinstance(in_date, str):
            form_date = int(calendar.timegm(time.strptime(in_date, '%Y-%m-%d')))
        else:
            form_date = str((datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=in_date)).date())
        return form_date

    # Private Static Method to Convert Eastern Time to UTC
    @staticmethod
    def _convert_to_utc(date, mask='%Y-%m-%d %H:%M:%S'):
        utc = pytz.utc
        eastern = pytz.timezone('US/Eastern')
        date_ = datetime.datetime.strptime(date.replace(" 0:", " 12:"), mask)
        date_eastern = eastern.localize(date_, is_dst=None)
        date_utc = date_eastern.astimezone(utc)
        return date_utc.strftime('%Y-%m-%d %H:%M:%S %Z%z')

    # Private method to parse page content from yahoo finance
    def _parse_finance(self, url, content):
        soup = BeautifulSoup(content, "html.parser")
        re_script = soup.find("script", text=re.compile("root.App.main"))
        if re_script is None:
            # no point in trying this over and over again so remember the parse failure
            self._cache[url] = ParseException(
                    "Parse error, no script in server response %d bytes from url: %s" % (
                    len(content), url))
            self._cache[url].data = content
            raise self._cache[url]
        # bs4 4.9.0 changed so text from scripts is no longer considered text
        script = re_script.text or re_script.string
        data = loads(re.search("root.App.main\s+=\s+(\{.*\})", script).group(1))
        try:
            self._cache[url] = data["context"]["dispatcher"]["stores"]
            if self._cache[url][:3] == 'U2F':
                self._cache[url] = _decrypt(data)
        except Exception as e:
            # no point in trying this over and over again so remember the parse failure
            self._cache[url] = ParseException(
                    "Failed, missing stores in %s bytes from '%s': %s" % (storekey, len(str(data)), url, e))
            self._cache[url].data = str(data)
            raise self._cache[url]

    # Private method to fetch and parse yahoo finance page
    def _fetch_finance(self, url):
        # Try to open the URL multiple times sleeping random time between tries
        rescode = 0
        for tries in range(READ_TRIES):
            if rescode == 404:
                # not found last time, won't succeed this time, run out the tries
                continue
            if tries:
                # this is a retry, don't hammer the server
                time.sleep((2 ** tries) / 2 + random.randrange(1, 5))
            rescode, response_content = fetch_url(url, self.activitycb)
            trace('rescode=%s' % rescode)
            if rescode == 200:
                self._parse_finance(url, response_content)
                break
            print("Fail try %d, code %d from %s" % (tries + 1, rescode, url), file=sys.stderr)
        else:
            print("Failed, code %d from %s" % (rescode, url), file=sys.stderr)
            # Raise a custom exception if we can't get the web page
            # exhausted all the tries so remember this failure
            self._cache[url] = URLOpenException(
                    "Server replied with HTTP %d code while opening the url: %s" % (
                    rescode, url))
            self._cache[url].data = "HTTP %d" % (rescode,)
            raise self._cache[url]

    # Private method to scrape data from yahoo finance
    def _scrape_finance(self, url):
        #print(f"scraping: {DEBUG} - {url!r}")
        if not self._cache.get(url):
            try:
                self._fetch_finance(url)
            except URLOpenException as e:
                trace('URLOpenException: %s' % e)
                self._cache[url].url = url
                self._cache[url].info = 'none'
            except ParseException as e:
                trace('ParseException: %s' % e)
                self._cache[url].url = url
                self._cache[url].info = 'none-ok'

        if isinstance(self._cache[url], Exception):
            trace('URLException: %s' % self._cache[url])
            raise self._cache[url]

        stores = self._cache[url]
        if DEBUG > 2:
            trace('stores: %s' % (stores,))
        else:
            trace('stores: x%d' % (len(stores),))
        return stores


    # Private static method to determine if a numerical value is in the data object being cleaned
    @staticmethod
    def _determine_numeric_value(value_dict):
        if 'raw' in value_dict.keys():
            numerical_val = value_dict['raw']
        else:
            numerical_val = None
        return numerical_val

    # Private method to format date serial string to readable format and vice versa
    def _format_time(self, in_time):
        form_date_time = datetime.datetime.fromtimestamp(int(in_time)).strftime('%Y-%m-%d %H:%M:%S')
        utc_dt = self._convert_to_utc(form_date_time)
        return utc_dt

    # Private method to return the a sub dictionary entry for the earning report cleaning
    def _get_cleaned_sub_dict_ent(self, key, val_list):
        sub_list = []
        for rec in val_list:
            sub_sub_dict = {}
            for k, v in rec.items():
                if k == 'date':
                    sub_sub_dict_ent = {k: v}
                else:
                    numerical_val = self._determine_numeric_value(v)
                    sub_sub_dict_ent = {k: numerical_val}
                sub_sub_dict.update(sub_sub_dict_ent)
            sub_list.append(sub_sub_dict)
        sub_ent = {key: sub_list}
        return sub_ent

    # Private method to process raw earnings data and clean
    def _clean_earnings_data(self, raw_data):
        cleaned_data = {}
        earnings_key = 'earningsData'
        financials_key = 'financialsData'
        for k, v in raw_data.items():
            if k == 'earningsChart':
                sub_dict = {}
                for k2, v2 in v.items():
                    if k2 == 'quarterly':
                        sub_ent = self._get_cleaned_sub_dict_ent(k2, v2)
                    elif k2 == 'currentQuarterEstimate':
                        numerical_val = self._determine_numeric_value(v2)
                        sub_ent = {k2: numerical_val}
                    else:
                        sub_ent = {k2: v2}
                    sub_dict.update(sub_ent)
                dict_ent = {earnings_key: sub_dict}
                cleaned_data.update(dict_ent)
            elif k == 'financialsChart':
                sub_dict = {}
                for k2, v2, in v.items():
                    sub_ent = self._get_cleaned_sub_dict_ent(k2, v2)
                    sub_dict.update(sub_ent)
                dict_ent = {financials_key: sub_dict}
                cleaned_data.update(dict_ent)
            else:
                if k != 'maxAge':
                    dict_ent = {k: v}
                    cleaned_data.update(dict_ent)
        return cleaned_data

    # Private method to clean summary and price reports
    def _clean_reports(self, raw_data):
        cleaned_dict = {}
        if raw_data is None:
            return None
        for k, v in raw_data.items():
            if 'Time' in k:
                formatted_utc_time = self._format_time(v)
                dict_ent = {k: formatted_utc_time}
            elif 'Date' in k:
                try:
                    formatted_date = v['fmt']
                except (KeyError, TypeError):
                    formatted_date = '-'
                dict_ent = {k: formatted_date}
            elif v is None or isinstance(v, str) or isinstance(v, int) or isinstance(v, float):
                dict_ent = {k: v}
            else:
                numerical_val = self._determine_numeric_value(v)
                dict_ent = {k: numerical_val}
            cleaned_dict.update(dict_ent)
        return cleaned_dict

    # Private Static Method to ensure ticker is URL encoded
    @staticmethod
    def _encode_ticker(ticker_str):
        encoded_ticker = ticker_str.replace('=', '%3D')
        return encoded_ticker

    # Private method to get time interval code
    def _build_historical_url(self, ticker, hist_oj):
        url = self._BASE_YAHOO_URL + self._encode_ticker(ticker) + '/history?period1=' + str(hist_oj['start']) + \
              '&period2=' + str(hist_oj['end']) + '&interval=' + hist_oj['interval'] + '&filter=history&frequency=' + \
              hist_oj['interval']
        return url

    # Private Method to clean the dates of the newly returns historical stock data into readable format
    def _clean_historical_data(self, hist_data, last_attempt=False):
        data = {}
        for k, v in hist_data.items():
            if k == 'eventsData':
                event_obj = {}
                if isinstance(v, list):
                    dict_ent = {k: event_obj}
                else:
                    for type_key, type_obj in v.items():
                        formatted_type_obj = {}
                        for date_key, date_obj in type_obj.items():
                            formatted_date_key = self.format_date(int(date_key))
                            cleaned_date = self.format_date(int(date_obj['date']))
                            date_obj.update({'formatted_date': cleaned_date})
                            formatted_type_obj.update({formatted_date_key: date_obj})
                        event_obj.update({type_key: formatted_type_obj})
                    dict_ent = {k: event_obj}
            elif 'date' in k.lower():
                if v is not None:
                    cleaned_date = self.format_date(v)
                    dict_ent = {k: {'formatted_date': cleaned_date, 'date': v}}
                else:
                    if last_attempt is False:
                        return None
                    else:
                        dict_ent = {k: {'formatted_date': None, 'date': v}}
            elif isinstance(v, list):
                sub_dict_list = []
                for sub_dict in v:
                    sub_dict['formatted_date'] = self.format_date(sub_dict['date'])
                    sub_dict_list.append(sub_dict)
                dict_ent = {k: sub_dict_list}
            else:
                dict_ent = {k: v}
            data.update(dict_ent)
        return data

    # Private Static Method to build API url for GET Request
    @staticmethod
    def _build_api_url(hist_obj, up_ticker):
        base_url = "https://query1.finance.yahoo.com/v8/finance/chart/"
        api_url = base_url + up_ticker + '?symbol=' + up_ticker + '&period1=' + str(hist_obj['start']) + '&period2=' + \
                  str(hist_obj['end']) + '&interval=' + hist_obj['interval']
        api_url += '&events=div|split|earn&lang=en-US&region=US'
        return api_url

    # Private Method to get financial data via API Call
    def _get_api_data(self, api_url):
        json_content = None
        for tries in range(READ_TRIES):
            if tries:
                time.sleep(random.randrange(10, 20))
            rescode, res_content = fetch_url(api_url, self.activitycb)
            try:
                if rescode == 200:
                    json_content = loads(res_content.decode('utf-8'))
                    break
            except:
                pass
        return json_content

    # Private Method to clean API data
    def _clean_api_data(self, api_url):
        raw_data = self._get_api_data(api_url)
        ret_obj = {}
        ret_obj.update({'eventsData': []})
        if raw_data is None:
            return ret_obj
        results = raw_data['chart']['result']
        if results is None:
            return ret_obj
        for result in results:
            tz_sub_dict = {}
            ret_obj.update({'eventsData': result.get('events', {})})
            ret_obj.update({'firstTradeDate': result['meta'].get('firstTradeDate', 'NA')})
            ret_obj.update({'currency': result['meta'].get('currency', 'NA')})
            ret_obj.update({'instrumentType': result['meta'].get('instrumentType', 'NA')})
            tz_sub_dict.update({'gmtOffset': result['meta']['gmtoffset']})
            ret_obj.update({'timeZone': tz_sub_dict})
            timestamp_list = result['timestamp']
            high_price_list = result['indicators']['quote'][0]['high']
            low_price_list = result['indicators']['quote'][0]['low']
            open_price_list = result['indicators']['quote'][0]['open']
            close_price_list = result['indicators']['quote'][0]['close']
            volume_list = result['indicators']['quote'][0]['volume']
            adj_close_list = result['indicators']['adjclose'][0]['adjclose']
            i = 0
            prices_list = []
            for timestamp in timestamp_list:
                price_dict = {}
                price_dict.update({'date': timestamp})
                price_dict.update({'high': high_price_list[i]})
                price_dict.update({'low': low_price_list[i]})
                price_dict.update({'open': open_price_list[i]})
                price_dict.update({'close': close_price_list[i]})
                price_dict.update({'volume': volume_list[i]})
                price_dict.update({'adjclose': adj_close_list[i]})
                prices_list.append(price_dict)
                i += 1
            ret_obj.update({'prices': prices_list})
        return ret_obj

    # Private Method to Handle Recursive API Request
    def _recursive_api_request(self, hist_obj, up_ticker, i=0):
        api_url = self._build_api_url(hist_obj, up_ticker)
        re_data = self._clean_api_data(api_url)
        cleaned_re_data = self._clean_historical_data(re_data)
        if cleaned_re_data is not None:
            return cleaned_re_data
        else:
            if i < 3:
                i += 1
                return self._recursive_api_request(hist_obj, up_ticker, i)
            else:
                return self._clean_historical_data(re_data, True)

    # Private Method to take scrapped data and build a data dictionary with
    def _create_dict_ent(self, up_ticker, statement_type, tech_type, report_name, hist_obj):
        #print(f"_create_dict_ent({up_ticker!r}, {statement_type!r}, {tech_type!r}, {report_name!r}, ...)")
        if statement_type == 'history':
            yahoo_url = self._build_historical_url(up_ticker, hist_obj)
            try:
                cleaned_re_data = self._recursive_api_request(hist_obj, up_ticker)
            except KeyError:
                try:
                    re_data = self._scrape_finance(yahoo_url)["HistoricalPriceStore"]
                    cleaned_re_data = self._clean_historical_data(re_data)
                except KeyError:
                    cleaned_re_data = None
            dict_ent = {up_ticker: cleaned_re_data}
        else:
            yahoo_url = self._BASE_YAHOO_URL + up_ticker + '/' +\
                self.YAHOO_FINANCIAL_TYPES[statement_type][0] + '?p=' + up_ticker
            try:
                re_data = time_report(self._scrape_finance, yahoo_url)["QuoteSummaryStore"]
            except KeyError:
                re_data = None
            try:
                if tech_type:
                    dict_ent = {up_ticker: re_data[tech_type]}
                else:
                    dict_ent = {up_ticker: re_data[u'' + report_name], 'dataType': report_name}
            except (KeyError, TypeError):
                # KeyError: ???
                # TypeError: when re_data is None
                dict_ent = {up_ticker: re_data, 'dataType': report_name}
        return dict_ent

    # Private method to return the stmt_id for the reformat_process
    def _get_stmt_id(self, statement_type, raw_data):
        stmt_id = ''
        i = 0
        for key in raw_data.keys():
            if key in self.YAHOO_FINANCIAL_TYPES[statement_type.lower()]:
                stmt_id = key
                i += 1
        if i != 1:
            return None
        return stmt_id

    # Private Method for the Reformat Process
    def _reformat_stmt_data_process(self, raw_data, statement_type):
        final_data_list = []
        if raw_data is not None:
            stmt_id = self._get_stmt_id(statement_type, raw_data)
            if stmt_id is None:
                return final_data_list
            hashed_data_list = raw_data[stmt_id]
            for data_item in hashed_data_list:
                data_date = ''
                sub_data_dict = {}
                for k, v in data_item.items():
                    if k == 'endDate':
                        data_date = v['fmt']
                    elif k != 'maxAge':
                        numerical_val = self._determine_numeric_value(v)
                        sub_dict_item = {k: numerical_val}
                        sub_data_dict.update(sub_dict_item)
                dict_item = {data_date: sub_data_dict}
                final_data_list.append(dict_item)
            return final_data_list
        else:
            return raw_data

    # Private Method to return subdict entry for the statement reformat process
    def _get_sub_dict_ent(self, ticker, raw_data, statement_type):
        form_data_list = self._reformat_stmt_data_process(raw_data[ticker], statement_type)
        return {ticker: form_data_list}

    # Public method to clear the cache
    def cache_clear(self):
        self._cache.clear()
        _url_cache.clear()

    # Public method to get time interval code
    def get_time_code(self, time_interval):
        interval_code = self._INTERVAL_DICT[time_interval.lower()]
        return interval_code

    # Public Method to get stock data
    def get_stock_data(self, statement_type='income', tech_type='', report_name='', hist_obj={}):
        data = {}
        for tick in self.ticker:
            exc = None
            try:
                dict_ent = time_report(self._create_dict_ent, tick, statement_type, tech_type, report_name, hist_obj)
                data.update(dict_ent)
            except URLOpenException as e:
                print("Warning! Ticker: %s: %s" % (tick, e), file=sys.stderr)
                exc = e
            except ParseException as e:
                print("Warning! Ticker: %s: %s" % (tick, e), file=sys.stderr)
                exc = e
            except ManagedException as e:
                print("Warning! Ticker: %s: %s" % (tick, e), file=sys.stderr)
                exc = e
            finally:
                if exc:
                    print("The process is still running...", file=sys.stderr)
                    if LOG_FAILURES:
                        now = time.strftime('%Y%m%dT%H%M%S')
                        sep = '-----' * 15
                        with open('/tmp/%s-%s.log' % (now[:8], tick), 'a+') as f:
                            print("Warning! Ticker: %s: %s" % (tick, exc), file=f)
                            print(f"get_stock_data({statement_type!r}, {tech_type!r}, {report_name!r}, ...)", file=f)
                            for eurl, edata in (e for e in self._cache.items() if isinstance(e, Exception)):
                                f.write('%s\nts: %s\nkey: %s\nurl: %s\ninfo: %s\ndata:\n%s\n' % (
                                    sep, now, eurl,
                                    edata.url if edata.data else 'none',
                                    edata.info if edata.data else 'none',
                                    sep
                                ))
                                f.write(edata.data or 'none')
                                f.write('\n%s\n' % (sep,))
        return data

    # Public Method to get technical stock data
    def get_stock_tech_data(self, tech_type):
        if tech_type == 'defaultKeyStatistics':
            return self.get_stock_data(statement_type='keystats', tech_type=tech_type)
        else:
            return self.get_stock_data(tech_type=tech_type)

    # Public Method to get reformatted statement data
    def get_reformatted_stmt_data(self, raw_data, statement_type):
        data_dict = {}
        sub_dict = {}
        data_type = raw_data['dataType']
        for tick in self.ticker:
            sub_dict_ent = self._get_sub_dict_ent(tick, raw_data, statement_type)
            sub_dict.update(sub_dict_ent)
        dict_ent = {data_type: sub_dict}
        data_dict.update(dict_ent)
        return data_dict

    # Public method to get cleaned summary and price report data
    def get_clean_data(self, raw_report_data, report_type):
        cleaned_data_dict = {}
        for tick in self.ticker:
            if report_type == 'earnings':
                try:
                    cleaned_data = self._clean_earnings_data(raw_report_data[tick])
                except:
                    cleaned_data = None
            else:
                try:
                    cleaned_data = self._clean_reports(raw_report_data[tick])
                except:
                    cleaned_data = None
            cleaned_data_dict.update({tick: cleaned_data})
        return cleaned_data_dict

    # Private method to handle dividend data requests
    def _handle_api_dividend_request(self, cur_ticker, start, end, interval):
        re_dividends = []
        test_url = 'https://query1.finance.yahoo.com/v8/finance/chart/' + cur_ticker + \
                   '?period1=' + str(start) + '&period2=' + str(end) + '&interval=' + interval + '&events=div'
        div_dict = self._get_api_data(test_url)['chart']['result'][0]['events']['dividends']
        for div_time_key, div_obj in div_dict.items():
            dividend_obj = {
                'date': div_obj['date'],
                'formatted_date': self.format_date(int(div_obj['date'])),
                'amount': div_obj.get('amount')
            }
            re_dividends.append(dividend_obj)
        return sorted(re_dividends, key=lambda div: div['date'])

    # Public method to get daily dividend data
    def get_stock_dividend_data(self, start, end, interval):
        interval_code = self.get_time_code(interval)
        re_data = {}
        for tick in self.ticker:
            try:
                div_data = self._handle_api_dividend_request(tick, start, end, interval_code)
                re_data.update({tick: div_data})
            except:
                re_data.update({tick: None})
        return re_data


# Class containing methods to create stock data extracts
class YahooFinancials(YahooFinanceETL):

    # Private method that handles financial statement extraction
    def _run_financial_stmt(self, statement_type, report_num, reformat):
        report_name = self.YAHOO_FINANCIAL_TYPES[statement_type][report_num]
        raw_data = self.get_stock_data(statement_type, report_name=report_name)
        return self.get_reformatted_stmt_data(raw_data, statement_type) if reformat else raw_data

    # Public Method for the user to get financial statement data
    def get_financial_stmts(self, frequency, statement_type, reformat=True):
        report_num = 1 if frequency == 'annual' else 2
        if isinstance(statement_type, str):
            data = self._run_financial_stmt(statement_type, report_num, reformat)
        else:
            data = {}
            for stmt_type in statement_type:
                re_data = self._run_financial_stmt(stmt_type, report_num, reformat)
                data.update(re_data)
        return data

    # Public Method for the user to get stock price data
    def get_stock_price_data(self, reformat=True):
        r = self.get_stock_tech_data('price')
        return self.get_clean_data(r, 'price') if reformat else r

    # Public Method for the user to return key-statistics data
    def get_key_statistics_data(self, reformat=True):
        r = self.get_stock_tech_data('defaultKeyStatistics')
        return self.get_clean_data(r, 'defaultKeyStatistics') if reformat else r

    # Public Method for the user to get stock earnings data
    def get_stock_earnings_data(self, reformat=True):
        r = self.get_stock_tech_data('earnings')
        return self.get_clean_data(r, 'earnings') if reformat else r

    # Public Method for the user to get stock summary data
    def get_summary_data(self, reformat=True):
        r = self.get_stock_tech_data('summaryDetail')
        return self.get_clean_data(r, 'summaryDetail') if reformat else r

    # Public Method for the user to get the yahoo summary url
    def get_stock_summary_url(self):
        return {t: "%s%s/?p=%s" % (self._BASE_YAHOO_URL, t, t) for t in self.ticker}

    # Public Method for the user to get stock quote data
    def get_stock_quote_type_data(self):
        return self.get_stock_tech_data('quoteType')

    # Public Method for user to get historical price data with
    def get_historical_price_data(self, start_date, end_date, time_interval):
        interval_code = self.get_time_code(time_interval)
        start = self.format_date(start_date)
        end = self.format_date(end_date)
        hist_obj = {'start': start, 'end': end, 'interval': interval_code}
        return self.get_stock_data('history', hist_obj=hist_obj)

    # Private Method for Functions needing stock_price_data
    def _stock_price_data(self, data_field):
        ret_obj = {}
        for tick in self.ticker:
            if self.get_stock_price_data()[tick] is None:
                ret_obj.update({tick: None})
            else:
                ret_obj.update({tick: self.get_stock_price_data()[tick].get(data_field)})
        return ret_obj

    # Private Method for Functions needing stock_price_data
    def _stock_summary_data(self, data_field):
        ret_obj = {}
        for tick in self.ticker:
            if self.get_summary_data()[tick] is None:
                ret_obj.update({tick: None})
            else:
                ret_obj.update({tick: self.get_summary_data()[tick].get(data_field)})
        return ret_obj

    # Private Method for Functions needing financial statement data
    def _financial_statement_data(self, stmt_type, stmt_code, field_name, freq):
        re_data = self.get_financial_stmts(freq, stmt_type)[stmt_code]
        data = {}
        for tick in self.ticker:
            try:
                date_key = re_data[tick][0].keys()[0]
            except:
                try:
                    date_key = list(re_data[tick][0].keys())[0]
                except:
                    date_key = None
            if date_key is not None:
                sub_data = re_data[tick][0][date_key][field_name]
                data.update({tick: sub_data})
            else:
                data.update({tick: None})
        return data

    # Public method to get daily dividend data
    def get_daily_dividend_data(self, start_date, end_date):
        start = self.format_date(start_date)
        end = self.format_date(end_date)
        return self.get_stock_dividend_data(start, end, 'daily')

    # Public Price Data Methods
    def get_current_price(self):
        return self._stock_price_data('regularMarketPrice')

    def get_current_change(self):
        return self._stock_price_data('regularMarketChange')

    def get_current_percent_change(self):
        return self._stock_price_data('regularMarketChangePercent')

    def get_current_volume(self):
        return self._stock_price_data('regularMarketVolume')

    def get_prev_close_price(self):
        return self._stock_price_data('regularMarketPreviousClose')

    def get_open_price(self):
        return self._stock_price_data('regularMarketOpen')

    def get_ten_day_avg_daily_volume(self):
        return self._stock_price_data('averageDailyVolume10Day')

    def get_three_month_avg_daily_volume(self):
        return self._stock_price_data('averageDailyVolume3Month')

    def get_stock_exchange(self):
        return self._stock_price_data('exchangeName')

    def get_market_cap(self):
        return self._stock_price_data('marketCap')

    def get_daily_low(self):
        return self._stock_price_data('regularMarketDayLow')

    def get_daily_high(self):
        return self._stock_price_data('regularMarketDayHigh')

    def get_currency(self):
        return self._stock_price_data('currency')

    # Public Summary Data Methods
    def get_yearly_high(self):
        return self._stock_summary_data('fiftyTwoWeekHigh')

    def get_yearly_low(self):
        return self._stock_summary_data('fiftyTwoWeekLow')

    def get_dividend_yield(self):
        return self._stock_summary_data('dividendYield')

    def get_annual_avg_div_yield(self):
        return self._stock_summary_data('trailingAnnualDividendYield')

    def get_five_yr_avg_div_yield(self):
        return self._stock_summary_data('fiveYearAvgDividendYield')

    def get_dividend_rate(self):
        return self._stock_summary_data('dividendRate')

    def get_annual_avg_div_rate(self):
        return self._stock_summary_data('trailingAnnualDividendRate')

    def get_50day_moving_avg(self):
        return self._stock_summary_data('fiftyDayAverage')

    def get_200day_moving_avg(self):
        return self._stock_summary_data('twoHundredDayAverage')

    def get_beta(self):
        return self._stock_summary_data('beta')

    def get_payout_ratio(self):
        return self._stock_summary_data('payoutRatio')

    def get_pe_ratio(self):
        return self._stock_summary_data('trailingPE')

    def get_price_to_sales(self):
        return self._stock_summary_data('priceToSalesTrailing12Months')

    def get_exdividend_date(self):
        return self._stock_summary_data('exDividendDate')

    # Financial Statement Data Methods
    def get_book_value(self):
        return self._financial_statement_data('balance', 'balanceSheetHistoryQuarterly',
                                              'totalStockholderEquity', 'quarterly')

    def get_ebit(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'ebit', 'annual')

    def get_net_income(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'netIncome', 'annual')

    def get_interest_expense(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'interestExpense', 'annual')

    def get_operating_income(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'operatingIncome', 'annual')

    def get_total_operating_expense(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'totalOperatingExpenses', 'annual')

    def get_total_revenue(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'totalRevenue', 'annual')

    def get_cost_of_revenue(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'costOfRevenue', 'annual')

    def get_income_before_tax(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'incomeBeforeTax', 'annual')

    def get_income_tax_expense(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'incomeTaxExpense', 'annual')

    def get_gross_profit(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'grossProfit', 'annual')

    def get_net_income_from_continuing_ops(self):
        return self._financial_statement_data('income', 'incomeStatementHistory',
                                              'netIncomeFromContinuingOps', 'annual')

    def get_research_and_development(self):
        return self._financial_statement_data('income', 'incomeStatementHistory', 'researchDevelopment', 'annual')

    # Calculated Financial Methods
    def get_earnings_per_share(self):
        price_data = self.get_current_price()
        pe_ratio = self.get_pe_ratio()
        ret_obj = {}
        for tick in self.ticker:
            if price_data[tick] is not None and pe_ratio[tick] is not None:
                ret_obj.update({tick: price_data[tick] / pe_ratio[tick]})
            else:
                ret_obj.update({tick: None})
        return ret_obj

    def get_num_shares_outstanding(self, price_type='current'):
        today_low = self._stock_summary_data('dayHigh')
        today_high = self._stock_summary_data('dayLow')
        cur_market_cap = self._stock_summary_data('marketCap')
        ret_obj = {}
        for tick in self.ticker:
            if cur_market_cap[tick] is not None:
                if price_type == 'current':
                    current = self.get_current_price()
                    if current[tick] is not None:
                        ret_obj.update({tick: cur_market_cap[tick] / current[tick]})
                    else:
                        ret_obj.update({tick: None})
                else:
                    if today_low[tick] is not None and today_high[tick] is not None:
                        today_average = (today_high[tick] + today_low[tick]) / 2
                        ret_obj.update({tick: cur_market_cap[tick] / today_average})
                    else:
                        ret_obj.update({tick: None})
            else:
                ret_obj.update({tick: None})
        return ret_obj
