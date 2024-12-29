from argparse import ArgumentParser
from base64 import b64encode
from json import dumps
from os import getenv
from playwright.sync_api import sync_playwright, Playwright
from requests import get
from shodan import APIError, Shodan


api_key = {
    'ipqualityscore': getenv('IPQS'),
    'shodan': getenv('SHODAN')
}


def save(results):

    fpath = '/app/results/candidates'
    comment = '<!---->'
    html = open('template.html').read()

    sorted_results = {}

    for e in sorted(results.items(), key = lambda kv: (kv[1]['ip_score'] + kv[1]['url_score'])):
        sorted_results[e[0]] = e[1]
        row = f'''<tr>
                    <td>{e[0]}</td>
                    <td><a href="https://{e[1]["hostname"]}">{e[1]["hostname"]}</a></td>
                    <td>{e[1]["ip_score"]}</td>
                    <td>{e[1]["url_score"]}</td>
                    <td><a href="https://{e[0]}"><img src="data:image/png;base64,{e[1]["screenshot"]}" width="50%" height="50%"/></a></td>
                </tr>'''
        html = html.replace(comment, row + '\n' + '\t'*4 + comment)
    
    open(f'{fpath}.json', 'w').write(dumps(sorted_results))
    open(f'{fpath}.html', 'w').write(html)


def visit(url, screenshot = False):
    try:
        with sync_playwright() as playwright:
            browser = playwright.firefox.launch(headless = screenshot)
            context = browser.new_context(ignore_https_errors = True)

            page = context.new_page()

            page.goto(url)

            if screenshot:
                ss = page.screenshot()
                browser.close()
                return b64encode(ss).decode()
            else:
                input('Press any key to continue...')
                browser.close()


    except Exception as e:
        print(f'visit() Error: {e}')
        if screenshot:
            return None


def get_url_score(hostname):

    results = get(f'https://ipqualityscore.com/api/json/url/{api_key["ipqualityscore"]}/https%3a%2f%2f{hostname}').json()
    try:
        ip_score = int(results['risk_score'])
        unsafe = results['unsafe']
        category = results['category']
    except:
        ip_score = 999
        unsafe = True
        category = 'Unknown'
    return ip_score, unsafe, category


def get_ip_score(ip):

    results = get(f'https://ipqualityscore.com/api/json/ip/{api_key["ipqualityscore"]}/{ip}').json()
    try:
        ip_score = int(results['fraud_score'])
    except:
        ip_score = 999
    return ip_score


def get_ips(search, limit):

    ips = {}

    try:
        s = Shodan(api_key['shodan'])
        results = s.search(search, limit = limit)

        for e in results['matches']:
            if 'ssl' in e:
                if not e['ssl']['cert']['expired']:
                    ips[e['ip_str']] = {
                        'cn': e['ssl']['cert']['subject'].get('CN', ''),
                        'host': e['http']['host'],
                        'hostnames': e['hostnames']
                    }

    except APIError as e:
        print(f'get_ips() Error: {e}')

    return ips


def parse_args():

    parser = ArgumentParser()
    parser.add_argument('-l', '--ip-limit', type = int, default = 100)
    parser.add_argument('-s', '--ip-search', type = str, default = 'has_ssl:true port:443 http.status:200 http.html:Home country:us')
    parser.add_argument('-i', '--ip-score', type = int, default = 0)
    parser.add_argument('-u', '--url-score', type = int, default = 0)

    return parser.parse_args() 


def main():

    args = parse_args()

    candidates = {}

    ips = get_ips(args.ip_search, args.ip_limit)
    for ip in ips:
        candidate = ips[ip]

        candidate['hostname'] = candidate['cn'].replace('*.', '')

        if ip == candidate['host']:
            print(f'IP: {candidate["host"]}')
            print(f'Hostname: {candidate["hostname"]}')
            print(f'TLS CN: {candidate["cn"]}')
            print(f'Other hostnames:')
            for h in sorted(candidate["hostnames"]):
                print(f'\t- {h}')
            
            if '.' in candidate['hostname']:

                candidate['ip_score'] = get_ip_score(ip)
                print(f'IP score = {candidate["ip_score"]}')

                candidate['url_score'], candidate['unsafe'], candidate['category'] = get_url_score(candidate['hostname'])

                print(f'URL score: {candidate["url_score"]}')
                print(f'Safe: {not candidate["unsafe"]}')
                print(f'Category: {candidate["category"]}')

                candidate['screenshot'] = visit(f'https://{ip}', True)

                if candidate['ip_score'] <= args.ip_score and candidate['url_score'] <= args.url_score:
                    answer = input('Would you like to visit the website? [N/y] ')
                    if answer == 'y':
                        visit(f'https://{ip}')

                candidates[ip] = candidate
            print('\n---\n')

    save(candidates)


if __name__ == '__main__':
    main()