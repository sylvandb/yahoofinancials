"""
==============================
The Yahoo Financials Module
==============================

Author: Connor Sanders
Changed: Sylvan Butler
Python3 only

Copyright (C) 2019 Connor Sanders
Copyright (C) 2021, 2022, 2023 Sylvan Butler
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


from .parse import YahooFinancials
from .exceptions import ManagedException, ParseException, URLOpenException, DecryptException
from .fetchurl import VERSTR, \
    fetch_stats, fetch_stats_hist_as_str, \
    set_debug, reset_headers


BROKEN = False
