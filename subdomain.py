import argparse
import asyncio
import aiodns
import itertools
import os
import re
import string
import sys
import time
from consle_width import getTerminalSize


class SubDomain(object):
    def __init__(self, domain, num=100, full=False, loop=None):
        self.__check_domain(domain)
        self.domain = domain
        self.project_directory = os.path.abspath(os.path.dirname(__file__))
        self.loop = loop if loop is not None else asyncio.get_event_loop()
        self.console_width = getTerminalSize()[0] - 2
        self.queue = asyncio.Queue(loop=self.loop)
        self.found_count = 0
        self.scan_count = 0
        self.num = num
        self.full = full
        self.start_time = time.time()
        dns_servers = self.load_dns_servers()
        self.resolver = aiodns.DNSResolver(timeout=0.1, nameservers=dns_servers, loop=self.loop)
        self.ip_dict = {}
        self.found_subs = set()
        self.__load_next_sub()
        self.__load_subnames()
        self.output = open(self.domain + '_' + time.strftime('%y%m%d_%H%M%S', time.localtime()) + '.txt', 'w')

    def __check_domain(self, domain):
        match = re.match(r'(?i)^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', domain)
        if not match:
            sys.exit("domain invaild")

    def load_dns_servers(self):
        with open('{pd}/db/servers.txt'.format(pd=self.project_directory)) as f:
            return [line.strip() for line in f.readlines()]

    def __test_server(self, server):
        pass

    def __generate_general_dicts(self, line):
        subnames = []
        letter_count = line.count('{letter}')
        number_count = line.count('{number}')
        letters = itertools.product(string.ascii_lowercase, repeat=letter_count)
        letters = [''.join(l) for l in letters]
        numbers = itertools.product(string.digits, repeat=number_count)
        numbers = [''.join(n) for n in numbers]
        for l in letters:
            iter_line = line.replace('{letter}' * letter_count, l)
            subnames.append(iter_line)
        number_dicts = []
        for gd in subnames:
            for n in numbers:
                iter_line = gd.replace('{number}' * number_count, n)
                number_dicts.append(iter_line)
        if len(number_dicts) > 0:
            return number_dicts
        else:
            return subnames

    def __load_subnames(self):
        print('[+] Load sub names ...')
        subnames = []
        filename = 'subnames_full.txt' if self.full else 'subnames.txt'
        with open('{pd}/db/'.format(pd=self.project_directory) + filename, encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower()
                if '#' in line or line == '':
                    continue
                if '{letter}' in line or '{number}' in line:
                    subnames += self.__generate_general_dicts(line)
                else:
                    subnames.append(line)
        for sub in subnames:
            self.queue.put_nowait(sub)

    def __load_next_sub(self):
        print('[+] Load next level subs ...')
        self.next_subs = []
        filename = 'next_sub_full.txt' if self.full else 'next_sub.txt'
        with open('{pd}/db/'.format(pd=self.project_directory) + filename, encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower()
                if '#' in line or line == '':
                    continue
                if '{letter}' in line or '{number}' in line:
                    self.next_subs += self.__generate_general_dicts(line)
                else:
                    self.next_subs.append(line)

    async def query(self):
        while not self.queue.empty():
            sub = await self.queue.get()
            try:
                if sub in self.found_subs:
                    continue
                full_domain = '{sub}.{domain}'.format(sub=sub, domain=self.domain)
                _sub = sub.split('.')[-1]
                self.scan_count += 1
                _msg = 'Domain:%s| %s Found| %s groups| %s scanned in %.1f seconds' % (
                    sub.ljust(32), self.found_count, self.queue.qsize(), self.scan_count,
                    time.time() - self.start_time)
                sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)))
                sys.stdout.flush()
                try:
                    ret = await self.resolver.query(full_domain, 'A')
                    self.found_subs.add(sub)
                    ret = [r.host for r in ret]
                    ips = ','.join(sorted(ret))
                    if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0']:
                        continue
                except aiodns.error.DNSError as e:
                    pass
                else:
                    try:
                        self.scan_count += 1
                        ret = await self.resolver.query(full_domain, 'CNAME')
                        cname = ret.cname.rstrip('.')
                        if cname.endswith(self.domain) and cname not in self.found_subs:
                            self.found_subs.add(cname)
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]
                            await self.queue.put(cname_sub)
                    except:
                        pass
                    if (_sub, ips) not in self.ip_dict:
                        self.ip_dict[(_sub, ips)] = 1
                    else:
                        self.ip_dict[(_sub, ips)] += 1
                        if self.ip_dict[(_sub, ips)] > 30:
                            continue
                    self.found_count += 1
                    _msg = full_domain.ljust(30) + ips
                    self.output.write(full_domain.ljust(30) + '\t' + ips + '\n')
                    self.output.flush()
                    sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)) + '\n')
                    sys.stdout.flush()
                    try:
                        await self.resolver.query('subdomain.' + full_domain, 'A')
                    except aiodns.error.DNSError as e:
                        err_code, err_msg = e.args[0], e.args[1]
                        if err_code == 4:
                            for next_sub in self.next_subs:
                                await self.queue.put(next_sub + '.' + sub)
                    except:
                        pass
            except Exception as e:
                import traceback
                traceback.print_exc()
            finally:
                self.queue.task_done()

    async def _run(self):
        workers = [asyncio.Task(self.query(), loop=self.loop)
                   for _ in range(self.num)]
        await self.queue.join()
        for worker in workers:
            worker.cancel()

    def run(self):
        try:
            self.loop.run_until_complete(self._run())
        except Exception as e:
            print(e)
        msg = "%s Found| %s scanned in %.1f seconds" % (
            self.found_count, self.scan_count, time.time() - self.start_time)
        print(msg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d qq.com")
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', dest='domain', help="Target Domain", required=True)
    parser.add_argument('-n', '--num', dest='num', help='Num of scan threads', default=100, type=int)
    parser.add_argument('-f', '--full', dest='full',
                        help='Full scan, NAMES FILE subnames_full.txt will be used to brute', action="store_true")
    args = parser.parse_args()
    domain = args.domain
    num = args.num
    full = args.full
    s = SubDomain(domain, num, full)
    s.run()
