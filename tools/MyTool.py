# coding=utf-8

import csv as csvv
import logging
import html
import pickle
import re
import subprocess

import pandas as pd

logger = logging.getLogger(__name__)


class csv:
    def __init__(self, *header):
        """
            header
                ex. cveMan("ID","発行日","更新日","概要")
        """
        self.delimiter = "{}\t"
        self.data_list = []
        #        out_line   = self._formater(*header)
        self.header = self._formater(*header)

    #        print(self.header)

    def __str__(self):
        out_string_list = [self.header]
        for data in self.data_list:
            out_string_list.append(data)
        return "\n".join(out_string_list)

    def _formater(self, *data):
        """
            文字列を返す
        """
        #        return ("{}\t"*len(data))[:-1].format(*data)
        return (self.delimiter * len(data))[:-1].format(*data)

    def addData(self, *data):
        out_line = self._formater(*data)
        self.data_list.append(out_line)

    def outList(self, with_header=True):
        out_line_list = []

        if with_header:
            out_line_list.append(self.header)

        for data in self.data_list:
            out_line_list.append(data)
        return out_line_list

    def outFile(self, out_path, with_header=True, enc="utf_8_sig", delimiter=','):
        with open(out_path, 'w', encoding=enc, newline="") as csvfile:
            writer = csvv.writer(csvfile, lineterminator='\n', delimiter=delimiter)
            if with_header:
                writer.writerow(self.header.split("\t"))

            for data in self.data_list:
                writer.writerow(data.split("\t"))

    def outFile2(self, out_path, with_header=True):
        out_line_list = []

        if with_header:
            out_line_list.append(self.header)

        for data in self.data_list:
            out_line_list.append(data)

        line = "\n".join(out_line_list)
        with open(out_path, "w") as f:
            f.write(line)


def trim_html_comment(content: str, HEAD_TAG="<!--", TAIL_TAG="-->") -> str:
    """
    htmlコメントを取り除く。
    :param content: string
    :param HEAD_TAG:
    :param TAIL_TAG:
    :return:
    """
    exculude_list = []
    #    start = 0
    comment_head = content.find(HEAD_TAG, 0)
    if comment_head == -1:
        return content

    comment_tail = 0
    while comment_head > 0:
        exculude_list.append(content[comment_tail:comment_head])
        comment_tail = content.find(TAIL_TAG, comment_head + 1)
        comment_tail = comment_tail + len(TAIL_TAG)
        comment_head = content.find(HEAD_TAG, comment_head + 1)
    return "\n".join(exculude_list)


def dev_contents(content, HEAD_TAG="<!--", TAIL_TAG="-->"):
    """
    contentを二つに分割する。
        1．HEAD_TAGとTAIL_TAGで囲まれた部分
        2．上記以外
    :param content: string
    :param HEAD_TAG:
    :param TAIL_TAG:
    :return:
    """
    exculude_list = []
    include_list = []
    #    start = 0
    comment_head = content.find(HEAD_TAG, 0)
    if comment_head == -1:
        return content, ""

    comment_tail = 0
    while comment_head > 0:
        exculude_list.append(content[comment_tail:comment_head])
        comment_tail = content.find(TAIL_TAG, comment_head + 1)
        comment_tail = comment_tail + len(TAIL_TAG)
        include_list.append(content[comment_head:comment_tail])
        comment_head = content.find(HEAD_TAG, comment_head + 1)
    return "\n".join(exculude_list), "\n".join(include_list)


def csv_to_html(csv_file_path, html_file_path, classes='result_table', index=False):
    html_string = '''
    <html>
      <head><meta charset="UTF-8">
      <title>Search Result</title>
      </head>
      <link rel="stylesheet" type="text/css" href="mystyle.css"/>
      <body>
        {table}
      </body>
    </html>.
    '''
    df = pd.read_csv(csv_file_path)
    # df.columns
    for ID, csv_id in enumerate(df['CVE-ID']):
        df['CVE-ID'][ID] = mod_cveid_for_html(csv_id)

    for ID, link_str in enumerate(df['参照']):
        if link_str:
            df['参照'][ID] = mod_linkstr_for_html(link_str)

    for ID, eid in enumerate(df['EID']):
        if eid.startswith('['):
            df['EID'][ID] = mod_eid_for_html(eid)

    for ID, pid in enumerate(df['PID']):
        if pid.startswith('['):
            df['PID'][ID] = mod_nessusid_for_html(pid)

    for ID, bid in enumerate(df['BID']):
        if bid.startswith('['):
            df['BID'][ID] = mod_bid_for_html(bid)

    for ID, cwe in enumerate(df['CWE']):
        if isinstance(cwe, str):
            df['CWE'][ID] = mod_cwe_for_html(cwe)
        else:
            df['CWE'][ID] = '-'

    for ID, jvnid in enumerate(df['JVN-ID']):
        if jvnid == '-':
            continue
        df['JVN-ID'][ID] = mod_jvnid_for_html(jvnid)

    for ID, r7id in enumerate(df['RAPID7']):
        if r7id.startswith('['):
            df['RAPID7'][ID] = mod_r7_for_html(r7id)

    pd.set_option('colheader_justify', 'center')

    table = df.to_html(classes=classes, escape=False, index=index)

    with open(html_file_path, 'w', encoding='utf-8') as f:
        f.write(html_string.format(table=table))


def csv_to_table(csv_file_path, classes='result_table', index=False):
    df = pd.read_csv(csv_file_path)
    pd.set_option('colheader_justify', 'center')
    table = df.to_html(classes=classes, index=index)
    return table


def mod_linkstr_for_html(link_str):
    new_link_list = []
    link_list = link_str.split('\n')
    for link in link_list:
        data = link.split()
        l = data[0]
        t = " ".join(data[1:]).replace('[', '').replace(']', '').replace("'", "")
        new_link_list.append(f'<li><a href="{l}"> {t}</a></li>')
    return '<ul>' + "".join(new_link_list) + '</ul>'


def _mod_linkstr_for_html(link_str):
    new_link_list = []
    link_list = link_str.split('\n')
    for link in link_list:
        data = link.split()
        l = data[0]
        t = " ".join(data[1:])
        new_link_list.append(f'<a href="{l}">{l} {t}</a>')
    return "<br>".join(new_link_list)


def mod_cveid_for_html(cveid_str):
    return f'<a href="https://nvd.nist.gov/vuln/detail/{cveid_str}"> {cveid_str} </a>'


def mod_jvnid_for_html(jvnid_str):
    # ['JVNDB-2020-009533', 'JVNDB-2020-009514']
    # https://jvndb.jvn.jp/ja/contents/2021/JVNDB-2021-001332.html
    # m = jvnid_str.split("-")[1]
    # i = "-".join(jvnid_str.split("-")[1:])
    # return f'<a href="https://jvndb.jvn.jp/ja/contents/{m}/{jvnid_str}.html"> {i} </a>'
    new_id_list = []
    id_list = jvnid_str[1:-1].replace(",", "").replace("'", "").split()
    if id_list:
        for ID in id_list:
            m = ID.split("-")[1]
            i = "-".join(ID.split("-")[1:])
            new_id_list.append(f'<a href="https://jvndb.jvn.jp/ja/contents/{m}/{ID}.html"> {i} </a>')
        return "<br>".join(new_id_list)
    else:
        return "-"


def mod_nessusid_for_html(nessusid_str):
    return mod_id_for_html(nessusid_str, "https://www.tenable.com/plugins/nessus/")
    # # ['147175', '147181']
    # new_nessusid_list = []
    # nessusid_list = nessusid_str[1:-1].replace(",", "").replace("'", "").split()
    # for nessusid in nessusid_list:
    #     new_nessusid_list.append(f'<a herf="https://www.tenable.com/plugins/nessus/{nessusid}"> {nessusid} </a>')
    # return "<br>".join(new_nessusid_list)


def mod_eid_for_html(eid_str):
    return mod_id_for_html(eid_str, "https://www.exploit-db.com/exploits/")
    # # ['147175', '147181']
    # new_eid_list = []
    # eid_list = eid_str[1:-1].replace(",", "").replace("'", "").split()
    # for eid in eid_list:
    #     new_eid_list.append(f'<a herf="https://www.exploit-db.com/exploits/{eid_str}"> {eid_str} </a>')
    # return "<br>".join(new_eid_list)


def mod_r7_for_html(r7_str):
    # ['/db/vulnerabilities/ubuntu-cve-2016-6662/',
    # '/db/vulnerabilities/php-cve-2016-3078/',
    # '/db/vulnerabilities/ubuntu-cve-2016-3078/']
    # print(r7_str)
    new_link_list = []
    link_list = r7_str[1:-1].replace(",", "").replace("'", "").split()
    for link in link_list:
        if link.endswith('/'):
            new_link_list.append(f'<a href="https://www.rapid7.com{link}"> {link.split("/")[-2]} </a>')
    return "<br>".join(new_link_list)


def mod_bid_for_html(bid_str):
    return mod_id_for_html(bid_str, "http://www.securityfocus.com/bid/")


def mod_id_for_html(id_str, base_url):
    # ['147175', '147181']
    new_id_list = []
    id_list = id_str[1:-1].replace(",", "").replace("'", "").split()
    for ID in id_list:
        new_id_list.append(f'<a href="{base_url}{ID}"> {ID} </a>')
    return "<br>".join(new_id_list)


def mod_cwe_for_html(cwe):
    # CWE-369
    # CWE-787\r\nCWE-787
    data = cwe.split('\n')
    new_data = []
    for d in data:
        new_data.append(f'<li>{d.strip()}</li>')
    return '<ul>' + "".join(new_data) + '</ul>'


def mod_file_path(file_path, trail_str=''):
    parts = file_path.split(".")
    new_file_path = "".join(parts[:-1]) + "_" + trail_str + ".html"
    return new_file_path


def get_link(content_str):
    pattern = r"(https?://[\w/:%#\$&\?\(\)~\.=\+\-]+)"
    p = re.compile(pattern)
    result = p.findall(content_str)
    return result


def ss_csv_to_html(csv_file_path, html_file_path, classes='result_table', index=False):
    main_html_file_path = html_file_path
    top_html_file_path = mod_file_path(html_file_path, "01")
    bottom_html_file_path = mod_file_path(html_file_path, "02")

    main_html_string = f'''
    <html>
      <head><meta charset="UTF-8">
      <title>Search Result</title>
      </head>
      <link rel="stylesheet" type="text/css" href="sstyle.css"/>
      <body>
        <div class="base">
          <iframe src="{top_html_file_path}" class="c_top" name="top" width="97%" height="40%"></iframe>
          <iframe src="{bottom_html_file_path}" class="c_bottom" name="bottom" width="97%" height="60%"></iframe>
        </div>
      </body>
    </html>
    '''

    top_html_string = '''
    <html>
      <head><meta charset="UTF-8">
      <title>Search Result</title>
      </head>
      <link rel="stylesheet" type="text/css" href="sstyle.css"/>
      <body>
        {table}
      </body>
    </html>
    '''

    bottom_html_string = '''
    <html>
      <head><meta charset="UTF-8">
      <title>Search Result</title>
      </head>
      <link rel="stylesheet" type="text/css" href="sstyle.css"/>
      <body>
        {table}
      </body>
    </html>
    '''

    pattern = r"(https?://[\w/:%#\$&\?\(\)~\.=\+\-]+)"

    with open(main_html_file_path, 'w', encoding='utf-8', newline="") as f:
        f.write(main_html_string)
    # with open(csv_file_path, "r", encoding='UTF-8') as f:
    #     reader = csvv.reader(f, delimiter="\t")
    #     header = next(reader)
    #     df = pd.DataFrame(reader)
    #     print(header)
    #     df.columns = header
    df = pd.read_csv(csv_file_path, encoding="utf8")

    # df_bottom = pd.DataFrame(
    #     {
    #         'EDB-ID': df['EDB-ID'],
    #         '攻撃データ': df['攻撃データ']
    #     }
    # )
    # df_bottom = df_bottom + pd.DataFrame(df['攻撃データ'])
    # for ID, _ in enumerate(df['EDB-ID']):
    #     df_bottom['EDB-ID'][ID] = _[2:-2]

    # for ID, _ in enumerate(df['攻撃データ']):
    #     __ = html.escape(_)
    #     df_bottom['攻撃データ'][ID] = f'<pre><code class="language-txt">{__}</code></pre>'

    lines = []
    for ID, _ in enumerate(df['EDB-ID']):
        edb_id = _[2:-2]
        # body = html.escape(df['攻撃データ'][ID]).replace("POC", "<b>POC</b>")
        body = html.escape(df['攻撃データ'][ID])
        body = body.replace("%TAB%", "    ")
        body = re.sub(pattern, r'<a href="\1">\1</a>', body)
        lines.append(f'<div class="card-id" id="i{edb_id}">{edb_id}</div>'
                     f'<div class="card-body" ><pre><code class="language-txt" >{body}</code></pre></div>')

    # pd.set_option('colheader_justify', 'center')
    # table = df_bottom.to_html(classes=classes, escape=False, index=index)

    with open(bottom_html_file_path, 'w', encoding='utf-8', newline="") as f:
        f.write(bottom_html_string.format(table="".join(lines)))

    df2 = pd.DataFrame(
        {
            'memo': f'<div contentEditable = "true"> 未調査 </div>',
            'EDB-ID': df['EDB-ID'],
            'Date': df['Date'],
            'Title': df['Title'],
            'Type': df['Type'],
            'Platform': df['Platform'],
            'Author': df['Author'],
            'CVE': df['CVE'],
        }
    )
    # MySearchSploit.SS.csv_header
    print(f"df.columns: {df.columns}")
    # ["Date", "Title", "Type", "Platform", "Author", "EDB-ID", "CVE", "攻撃データ"]

    for ID, _ in enumerate(df['Date']):
        df2['Date'][ID] = _[2:-2]

    for ID, _ in enumerate(df['Title']):
        edb_id = df["EDB-ID"][ID][2:-2]
        df2['Title'][ID] = f'<a href="https://www.exploit-db.com/exploits/{edb_id}"> {_} </a>'

    for ID, _ in enumerate(df['Type']):
        df2['Type'][ID] = _[2:-2]

    for ID, _ in enumerate(df['Platform']):
        df2['Platform'][ID] = _[2:-2]

    for ID, _ in enumerate(df['Author']):
        df2['Author'][ID] = _[2:-2]

    for ID, _ in enumerate(df['EDB-ID']):
        edb_id = _[2:-2]
        df2['EDB-ID'][ID] = f'<a href="{bottom_html_file_path}#i{edb_id}" target="bottom"> {edb_id} </a>'
        # df2['EDB-ID'][ID] = _[2:-2]

    for ID, _ in enumerate(df['CVE']):
        new_list = []
        _list = _[1:-1].replace(",", "").replace("'", "").split()
        for _ in _list:
            new_list.append(f'<a href="https://nvd.nist.gov/vuln/detail/CVE-{_}"> {_} </a>')
        df2['CVE'][ID] = "<br>".join(new_list)

    # for ID, _ in enumerate(df['攻撃データ']):
    #     # print(_, type(_), _[1:-1])
    #     # df['攻撃データ'][ID] = _[1:-1]
    #     df['攻撃データ'][ID] = f'<div contentEditable = "true"> ? </div>'

    pd.set_option('colheader_justify', 'center')

    table = df2.to_html(classes=classes, escape=False, index=index)

    with open(top_html_file_path, 'w', encoding='utf-8') as f:
        f.write(top_html_string.format(table=table))


def csv_to_html4ss(csv_file_path, html_file_path, classes='result_table', index=False):
    main_html_file_path = html_file_path
    top_html_file_path = mod_file_path(html_file_path, "01")
    bottom_html_file_path = mod_file_path(html_file_path, "02")

    main_html_string = f'''
    <html>
      <head><meta charset="UTF-8">
      <title>Search Result</title>
      </head>
      <link rel="stylesheet" type="text/css" href="sstyle.css"/>
      <body>
        <div class="base">
          <iframe src="{top_html_file_path}" class="c_top" name="top" width="97%" height="40%"></iframe>
          <iframe src="{bottom_html_file_path}" class="c_bottom" name="bottom" width="97%" height="60%"></iframe>
        </div>
      </body>
    </html>
    '''

    top_html_string = '''
    <html>
      <head><meta charset="UTF-8">
      <title>Search Result</title>
      </head>
      <link rel="stylesheet" type="text/css" href="sstyle.css"/>
      <body>
        {table}
      </body>
    </html>
    '''

    bottom_html_string = '''
    <html>
      <head><meta charset="UTF-8">
      <title>Search Result</title>
      </head>
      <link rel="stylesheet" type="text/css" href="sstyle.css"/>
      <body>
        {table}
      </body>
    </html>
    '''

    pattern = r"(https?://[\w/:%#\$&\?\(\)~\.=\+\-]+)"

    with open(main_html_file_path, 'w', encoding='utf-8', newline="") as f:
        f.write(main_html_string)

    df = pd.read_csv(csv_file_path, encoding="utf8")

    lines = []
    for ID, _ in enumerate(df['EDB-ID']):
        edb_id = _
        # body = html.escape(df['攻撃データ'][ID]).replace("POC", "<b>POC</b>")
        body = html.escape(df['body'][ID])
        body = body.replace("%TAB%", "    ")
        body = re.sub(pattern, r'<a href="\1">\1</a>', body)
        lines.append(f'<div class="card-id" id="i{edb_id}">{edb_id}</div>'
                     f'<div class="card-body" ><pre><code class="language-txt" >{body}</code></pre></div>')

    # pd.set_option('colheader_justify', 'center')
    # table = df_bottom.to_html(classes=classes, escape=False, index=index)

    with open(bottom_html_file_path, 'w', encoding='utf-8', newline="") as f:
        f.write(bottom_html_string.format(table="".join(lines)))

    df2 = pd.DataFrame(
        {
            # '攻撃データ': f'<div contentEditable = "true"> 未調査 </div>',
            '攻撃データ': df['Exploit'],
            'EDB-ID': df['EDB-ID'],
            'Date': df['Date'],
            'Title': df['Title'],
            'Type': df['Type'],
            'Platform': df['Platform'],
            'Author': df['Author'],
            'CVE': df['CVE'],
        }
    )
    # MySearchSploit.SS.csv_header
    # print(f"df.columns: {df.columns}")
    # ["Date", "Title", "Type", "Platform", "Author", "EDB-ID", "CVE", "攻撃データ"]

    for ID, _ in enumerate(df['Date']):
        # df2['Date'][ID] = _
        df2.loc[ID, 'Date'] = _

    for ID, _ in enumerate(df['Title']):
        edb_id = df["EDB-ID"][ID]
        # df2['Title'][ID] = f'<a href="https://www.exploit-db.com/exploits/{edb_id}" target=”_blank” > {_} </a>'
        df2.loc[ID, 'Title'] = f'<a href="https://www.exploit-db.com/exploits/{edb_id}" target=”_blank” > {_} </a>'

    for ID, _ in enumerate(df['Type']):
        # df2['Type'][ID] = _
        df2.loc[ID, 'Type'] = _

    for ID, _ in enumerate(df['Platform']):
        # df2['Platform'][ID] = _
        df2.loc[ID, 'Platform'] = _

    for ID, _ in enumerate(df['Author']):
        # df2['Author'][ID] = _
        df2.loc[ID, 'Author'] = _

    for ID, _ in enumerate(df['EDB-ID']):
        edb_id = _
        # df2['EDB-ID'][ID] = f'<a href="{bottom_html_file_path}#i{edb_id}" target="bottom"> {edb_id} </a>'
        df2.loc[ID, 'EDB-ID'] = f'<a href="{bottom_html_file_path}#i{edb_id}" target="bottom"> {edb_id} </a>'
        # df2['EDB-ID'][ID] = _[2:-2]

    for ID, _ in enumerate(df['CVE']):
        new_list = []
        _list = _[1:-1].replace(",", "").replace("'", "").split()
        for _ in _list:
            new_list.append(f'<a href="https://nvd.nist.gov/vuln/detail/CVE-{_}"  target=”_blank”> {_} </a>')
        # df2['CVE'][ID] = "<br>".join(new_list)
        df2.loc[ID, 'CVE'] = "<br>".join(new_list)

    for ID, _ in enumerate(df2['攻撃データ']):
        if isinstance(_, str):
            value = _.replace("\n", "<BR>")
            df2.loc[ID, '攻撃データ'] = f'<div contentEditable = "true"> {value} </div>'
        else:
            df2.loc[ID, '攻撃データ'] = "不明"
    #     # print(_, type(_), _[1:-1])
    #     # df['攻撃データ'][ID] = _[1:-1]
    #     df['攻撃データ'][ID] = f'<div contentEditable = "true"> ? </div>'

    pd.set_option('colheader_justify', 'center')

    table = df2.to_html(classes=classes, escape=False, index=index)

    with open(top_html_file_path, 'w', encoding='utf-8') as f:
        f.write(top_html_string.format(table=table))


def save_db(db_info, db_file):
    with open(db_file, 'wb') as f:
        pickle.dump(db_info, f)


def load_db(db_file):
    with open(db_file, 'rb') as f:
        db_info = pickle.load(f)
        return db_info


def shell_command(command_line, dispcoding='utf-8'):
    """
    command_lineで与えられたシェルコマンドを実行し、標準出力を返す
    !!! Linux OnlY   !!!
    :param command_line:
    :param dispcoding:
    :return:
    """
    result = (
        subprocess.Popen(command_line, stdout=subprocess.PIPE, shell=True).communicate()[0]
    ).decode(dispcoding)
    return result


def get_text(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        contents = f.read()
    return contents
