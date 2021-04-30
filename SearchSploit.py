# coding=utf-8

import datetime
import logging
import os

from tools import MyTool, MySearchSploit, MyHttp
import setting

LOG_FILE = '../SearchSploit.log'

# フォーマットを指定 (https://docs.python.jp/3/library/logging.html#logrecord-attributes)
_logfile_formatting = " ".join([
    '%(asctime)s',
    '%(levelname)-8s',
    '[%(module)s#%(funcName)s',
    '%(lineno)d]',
    '%(message)s'])

_console_formatting = " ".join([
    '%(asctime)s',
    '[%(levelname)-8s]',
    # '[%(module)s#%(funcName)s',
    # '%(lineno)d]',
    '%(message)s'])

logger = logging.getLogger(__name__)

# ログファイル
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter(_logfile_formatting))

# コンソール
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter(_console_formatting))

logger.setLevel(logging.DEBUG)
MySearchSploit.logger.setLevel(logging.DEBUG)
MyTool.logger.setLevel(logging.DEBUG)
MyHttp.logger.setLevel(logging.DEBUG)

logger.addHandler(ch)
MySearchSploit.logger.addHandler(ch)
MyTool.logger.addHandler(ch)
MyHttp.logger.addHandler(ch)

logger.addHandler(fh)
MySearchSploit.logger.addHandler(fh)
MyTool.logger.addHandler(fh)
MyHttp.logger.addHandler(fh)

#######################################
# setting
#######################################
csv_header = ["Date", "Title", "Type", "Platform", "Author", "EDB-ID", "URL", "Path", "CVE", "Exploit", "body"]

search_start_date = setting.search_start_date

# 検索キーワード
keyword_set_list = setting.keyword_set_list

#######################################


def main():
    # html生成のみの処理
    if setting.html_only and setting.html_only["csv"] and setting.html_only["html"]:
        csv_filename = f'{setting.html_only["csv"]}.csv'
        if not os.path.exists(csv_filename):
            logger.error(f"csv file not exist {csv_filename}")
            return

        html_filename = f'{setting.html_only["html"]}.html'
        if os.path.exists(html_filename):
            logger.error(f"html file exist {html_filename}")
            return

        MyTool.csv_to_html4ss(csv_filename, html_filename)
        return

    now = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    pre = f"{search_start_date.replace('-','')}-{now}"

    if setting.download_folder == "%DATE%":
        dl_dir = pre
    else:
        dl_dir = setting.download_folder

    if not os.path.exists(dl_dir):
        MyTool.shell_command(f"mkdir {dl_dir}")

    merged_json_data_list = []

    # keyword_set_count = len(keyword_set_list)
    for keyword_set in keyword_set_list:
        # keyword_count = len(keyword_set.keys())
        logger.debug(f"keyword_set: {keyword_set}")

        merged_json_data = MySearchSploit.proc_keyword_set(keyword_set, search_start_date)

        merged_json_data_list.append(merged_json_data)
        logger.debug(f"merged_json_data_list: {merged_json_data_list}")

    # CVE情報取得
    MySearchSploit.add_cve(merged_json_data_list, dl_dir)

    for json_data in merged_json_data_list:
        # CSV出力
        keyword = MySearchSploit.convert_filename(";".join(json_data['SEARCH']))
        data_count = len(json_data["RESULTS_EXPLOIT"].keys())
        csv_filename = f"{pre}_{keyword}_{data_count}.csv"

        o = MyTool.csv(*csv_header)

        data_list_list = []
        for title in json_data["RESULTS_EXPLOIT"].keys():
            item = json_data["RESULTS_EXPLOIT"][title]
            logger.debug(f'item["Date"]: {item}')
            data_list = (
                item["Date"].__str__(),
                item["Title"].__str__(),
                item["Type"].__str__(),
                item["Platform"].__str__(),
                item["Author"].__str__(),
                item["EDB-ID"].__str__(),
                item["URL"].__str__(),
                item["Path"].__str__(),
                item["CVE"].__str__(),
                item["Exploit"].__str__(),
                item["body"].__str__(),
            )
            data_list_list.append(data_list)

        for data in sorted(data_list_list, key=lambda x: x[0], reverse=True):
            o.addData(
                data[0],
                data[1],
                data[2],
                data[3],
                data[4],
                data[5],
                data[6],
                data[7],
                data[8],
                data[9],
                data[10].replace('\t', '%TAB%'),
            )

        o.outFile(csv_filename)
        # HTML出力
        html_filename = f"{pre}_{keyword}.html"
        MyTool.csv_to_html4ss(csv_filename, html_filename)

    return merged_json_data_list


if __name__ == '__main__':
    main()
