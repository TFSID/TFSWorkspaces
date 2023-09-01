import re
from logging import DEBUG
from urllib.parse import urljoin, urlencode, unquote
from utils.blacklist import is_blacklisted
from utils.helper import setup_logger, validate_url
from libs.html_parser import NativeHTMLParser
from libs.fetch import FetchRequest

logger = setup_logger(name='Aol')


class Aol:
    base_url = 'https://www.aol.com'
    search_url = 'https://search.aol.com'

    def __init__(self, debug=False):
        self.debug = debug
        self.query = {}
        self.fetch = FetchRequest()
        self.filtering = True

        if self.debug:
            logger.setLevel(DEBUG)

    def search(self, keyword):
        self.query.update({'q': str(keyword)})
        search_url = self.build_query()
        if search_url:
            search_url = urljoin(self.search_url, search_url)

        return self.search_run(search_url)

    def search_run(self, url):
        result = []
        if not url:
            return result

        duplicate_page = 0
        empty_page = 0
        headers = {'Referer': self.base_url}
        page = 1
        while True:
            if self.debug:
                logger.debug('Page: %s %s' % (page, url))
            else:
                logger.info('Page: %s' % page)

            html = self.fetch.get(url=url, headers=headers)
            links = self.get_links(html)

            if not links:
                empty_page += 1
                if page > 1:
                    break
            else:
                duplicate = True
                for link in links:
                    if self.filtering:
                        if is_blacklisted(link):
                            logger.debug('[BLACKLIST] %s' % link)
                            continue

                    if link not in result:
                        duplicate = False
                        result.append(link)
                        logger.info(link)
                    else:
                        logger.debug('[EXIST] %s' % link)

                if duplicate:
                    duplicate_page += 1

            if duplicate_page >= 3:
                break

            if empty_page >= 2:
                break

            next_page = self.get_next_page(html)
            if next_page and next_page != url:
                headers.update({'Referer': url})
                url = next_page
            else:
                break
            page += 1

        result = list(dict.fromkeys(result))
        logger.info('Total links: %d' % len(result))

        return result

    def build_query(self, html=None):
        search_url = ''
        if not html:
            html = self.fetch.get(self.base_url)

        _parser = NativeHTMLParser()
        _parser.feed(str(html))
        _parser.close()

        if _parser.root is None:
            return search_url

        form_header = _parser.root.find('.//form[@id="header-form"]')

        if form_header:
            search_url = form_header.get('action')
            inputs = form_header.findall('.//input[@type="hidden"]')
            for inp in inputs:
                _name = inp.get('name')
                _value = inp.get('value')
                if not _name:
                    continue

                if _name != 'q':
                    self.query.update({_name: _value or ''})

        if search_url:
            search_url = '%s?%s' % (search_url, urlencode(self.query))

        return search_url

    @staticmethod
    def get_links(html):
        result = []
        if not html:
            return result

        patern_url = r'\/RU=(.*?)\/RK='

        _parser = NativeHTMLParser()
        _parser.feed(str(html))
        _parser.close()

        if _parser.root is None:
            return result

        links = _parser.root.findall('.//a[@referrerpolicy="origin"]')

        for link in links:
            _class = link.get('class')
            _href = link.get('href')
            if _class and re.search(r'ac-algo', _class, re.I):
                temp_url = _href
                web_url = re.search(patern_url, temp_url, re.I)
                if web_url:
                    try:
                        valid_url = validate_url(unquote(web_url.group(1)))
                        if valid_url:
                            result.append(valid_url)
                    except IndexError:
                        pass

        if result:
            result = list(dict.fromkeys(result))

        return result

    def get_next_page(self, html):
        next_page = ''
        if not html:
            return next_page

        _parser = NativeHTMLParser()
        _parser.feed(str(html))
        _parser.close()

        if _parser.root is None:
            return next_page

        find_next_page = _parser.root.find('.//a[@class="next"]')
        if find_next_page is not None:
            _href = find_next_page.get('href')
            if _href:
                next_page = validate_url(urljoin(self.search_url, _href))

        return next_page


if __name__ == '__main__':
    import sys
    import argparse
    import json
    try:
        parser = argparse.ArgumentParser(usage='%(prog)s [options]')
        # noinspection PyProtectedMember
        parser._optionals.title = 'Options'
        parser.add_argument('-k', '--keyword',
                            dest='keyword',
                            help='Keyword to search',
                            action='store')
        parser.add_argument('-s', '--save',
                            dest='save_output',
                            help='Save Output results',
                            action='store_true')
        parser.add_argument('-o', '--output',
                            dest='output_file',
                            help='Output results (default aol_results.txt)',
                            default='aol_results.txt',
                            action='store')

        args = parser.parse_args()
        if not args.keyword:
            parser.print_help()
            sys.exit('[!] Keyword required')

        eng = Aol()
        res = eng.search(args.keyword)

        if args.save_output:
            if res:
                for rlink in res:
                    with open(args.output_file, 'a', encoding='utf-8', errors='replace') as f:
                        try:
                            f.write('%s\n' % rlink)
                        except UnicodeEncodeError:
                            logger.error(rlink)
        else:
            print(json.dumps(res, indent=2, default=str))
    except KeyboardInterrupt:
        sys.exit('KeyboardInterrupt')
