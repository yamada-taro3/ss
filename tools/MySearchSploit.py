# coding=utf-8

import datetime
import json
import logging
import os
from time import sleep

from bs4 import BeautifulSoup

from tools import MyHttp
from tools import MyTool
import setting

logger = logging.getLogger(__name__)


def make_param(keyword, param_set, add_w=False, add_j=True):
    """

    :param keyword:
    :param param_set:
    :param add_w:
    :param add_j:
    :return:
    """
    search_option_list = []
    if param_set["CaseSensitive"]:
        search_option_list.append("c")

    if param_set["Exect"]:
        search_option_list.append("e")

    if param_set["Strict"]:
        search_option_list.append("s")

    if param_set["Title"]:
        search_option_list.append("t")

    if add_j:
        search_option_list.append("j")

    if add_w:
        search_option_list.append("w")

    search_option = "".join(search_option_list)

    if param_set["ExculudeWord"]:
        exculude_word = f'--exclude="{"|".join(param_set["ExculudeWord"])}"'
    else:
        exculude_word = ""

    param_str = f'-{search_option} {keyword} {exculude_word}'
    logger.debug(f"param_str: {param_str}")
    return param_str


def proc_keyword_set(keyword_set, search_start_date):
    merged_json_data = {"SEARCH": [],
                        "DB_PATH_EXPLOIT": "",
                        "RESULTS_EXPLOIT": {}}

    for keyword in keyword_set.keys():
        logger.debug(f"keyword: {keyword}")

        param_str = make_param(keyword, keyword_set[keyword])
        # 同じ検索条件の場合はskipする。
        if param_str in merged_json_data["SEARCH"]:
            logger.debug(f"skip param_str: {param_str}")
            continue
        else:
            merged_json_data["SEARCH"].append(param_str)

        # ローカルの情報サーチ
        result = MyTool.shell_command(f'searchsploit {param_str}')
        local_json_data = json.loads(result)

        # リモートの情報サーチ
        param_w_str = make_param(keyword, keyword_set[keyword], add_w=True)
        result = MyTool.shell_command(f'searchsploit {param_w_str}')
        remote_json_data = json.loads(result)

        # ローカルのパスは変わらないはずなので無条件上書きする。
        merged_json_data["DB_PATH_EXPLOIT"] = local_json_data["DB_PATH_EXPLOIT"]

        start_dt = datetime.datetime.strptime(search_start_date, '%Y-%m-%d')
        logger.debug(f"merged_json_data: {merged_json_data}")

        # 日付でフィルタしつつ、リモートをマージする
        for local_item in local_json_data["RESULTS_EXPLOIT"]:
            item_dt = datetime.datetime.strptime(local_item["Date"], '%Y-%m-%d')
            # 指定より古い日付のデータはskip
            if item_dt < start_dt:
                logger.debug(f"skip item_dt < start_dt {item_dt} {start_dt}")
                continue

            merge_item(merged_json_data["RESULTS_EXPLOIT"],
                       local_item,
                       remote_json_data["RESULTS_EXPLOIT"])

    return merged_json_data


def merge_item(merged_exploits, local_exploits, remote_exploits):
    """

    :param merged_exploits:
    :param local_exploits:
    :param remote_exploits:
    :return:
    """

    # 重複する場合は追加しない
    if local_exploits["Title"] in merged_exploits.keys():
        return

    title = local_exploits["Title"]
    # まず、merged_json_dataにlocal_json_dataを追加する。
    merged_exploits[title] = local_exploits

    # "Path"の拡張子がtxtの場合
    filepath = merged_exploits[title]["Path"]
    file_ext = os.path.splitext(filepath)[-1]
    if file_ext.lower() == '.txt':
        merged_exploits[title]["body"] = MyTool.get_text(filepath)
    else:
        merged_exploits[title]["body"] = filepath

    # 次に、merged_json_dataのItemにremoteのURLをマージする。
    for r_exploit in remote_exploits:
        if r_exploit["Title"] != title:
            continue

        merged_exploits[title]["URL"] = r_exploit["URL"]
        return


def convert_filename(filename):
    logger.debug(f"filename: {filename}")
    return filename.replace('"', "'").replace('|', ';')


def httpget_data(url):
    # response = MyHttp2.get_request(item['URL'], {})
    data = ""
    logger.debug(f'url: {url}')
    body = MyHttp.get_request3(url)
    if body:
        soup = BeautifulSoup(body, 'html.parser')
        if soup:
            data = parse_data(soup)
            logger.debug(f"=>取得OK")
        else:
            logger.debug(f"=>取得エラー soup is NULL")
    else:
        logger.debug(f"=>取得エラー body is NULL")

    sleep(3)

    return data


def parse_data(soup):
    r = {
        "title": "get error",
        "body": "get error",
        "Date_list": ["get error"],
        "Type_list": ["get error"],
        "Platform_list": ["get error"],
        "EDBID_list": ["get error"],
        "CVE_list": ["get error"],
        "Author_list": ["get error"],
    }
    if not soup:
        return r

    r["title"] = soup.find('title').text

    r["body"] = soup.find('pre').text

    h6_tag_list = soup.select('h4:-soup-contains("Date:") ~ h6')
    # logger.debug(f"Date:{h6_tag_list}")
    r["Date_list"] = [h6_tag.get_text(strip=True) for h6_tag in h6_tag_list if h6_tag]

    h6_tag_list = soup.select('h4:-soup-contains("Type:") ~ h6')
    # logger.debug(f"Type:{h6_tag_list}")
    r["Type_list"] = [h6_tag.get_text(strip=True) for h6_tag in h6_tag_list if h6_tag]

    h6_tag_list = soup.select('h4:-soup-contains("Platform:") ~ h6')
    # logger.debug(f"Platform:{h6_tag_list}")
    r["Platform_list"] = [h6_tag.get_text(strip=True) for h6_tag in h6_tag_list if h6_tag]

    h6_tag_list = soup.select('h4:-soup-contains("EDB-ID:") ~ h6')
    # logger.debug(f"EDB-ID:{h6_tag_list}")
    r["EDBID_list"] = [h6_tag.get_text(strip=True) for h6_tag in h6_tag_list if h6_tag]

    h6_tag_list = soup.select('h4:-soup-contains("Author:") ~ h6')
    # logger.debug(f"h6_tag_list:{h6_tag_list}")
    r["Author_list"] = [h6_tag.get_text(strip=True) for h6_tag in h6_tag_list if h6_tag]

    h6_tag_list = soup.select('h4:-soup-contains("CVE:") ~ h6')
    logger.debug(f"CVE:{h6_tag_list}")
    a_tag_list = h6_tag_list[0].find_all('a')
    logger.debug(f"a_tag_list:{a_tag_list}")
    r["CVE_list"] = [a_tag.get_text(strip=True) for a_tag in a_tag_list if a_tag]
    # r["CVE_list"] = [h6_tag.get_text(strip=True) for h6_tag in h6_tag_list if h6_tag]

    return r


def add_cve(json_data_list, pre):
    # EDB-ID単位で取得するので、EDB毎のデータベースを作成する。
    # キー: EDB-ID 値: CVEとBody部分   {EDB-ID: {"CVE":[], "body": ""}}
    http_get_data = {}
    keyword_set_count = len(json_data_list)
    for ID1, json_data in enumerate(json_data_list):
        keyword = json_data["SEARCH"]
        logger.info(f"{keyword}({ID1 + 1}/{keyword_set_count})")
        title_count = len(json_data["RESULTS_EXPLOIT"].keys())
        for ID2, title in enumerate(json_data["RESULTS_EXPLOIT"].keys()):
            edb_id = json_data["RESULTS_EXPLOIT"][title]["EDB-ID"]
            logger.info(f"  {edb_id}({ID2+1}/{title_count})")

            item = json_data["RESULTS_EXPLOIT"][title]

            if item["EDB-ID"] in http_get_data.keys():
                item["CVE"] = http_get_data[item["EDB-ID"]]["CVE"]
                # item["body"] = http_get_data[item["EDB-ID"]]["body"]
            else:
                data = httpget_data(item["URL"])
                logger.debug(f"data: {data}")
                item["CVE"] = data["CVE_list"]
                # item["body"] = data["body"]
                logger.debug(f"item: {item}")
                add_exploit(item, pre)


def add_exploit(item, pre):
    logger.debug(f'item["Path"]: {item["Path"]}')
    path_ext = os.path.splitext(item["Path"])[-1].lower()

    if path_ext in setting.source_ext:
        # ローカルコピーする。
        dst_dir = f'{pre}/{item["EDB-ID"]}'
        MyTool.shell_command(f"mkdir -p {dst_dir}")
        command_line = f'cp {item["Path"]} {dst_dir}'
        logger.debug(f"command_line: {command_line}")
        MyTool.shell_command(command_line)
        item["Exploit"] = f"〇({path_ext})"

    elif path_ext == '.txt':
        # pattern = r"(https?://[\w/:%#\$&\?\(\)~\.=\+\-]+)"
        # bodyを解析し、リンクを抽出する。
        link_list = MyTool.get_link(item["body"])
        logger.debug(f"link_list: {link_list}")

        msg_list = []
        for link in link_list:
            ext = os.path.splitext(link)[-1].lower()
            if not ext:
                logger.debug(f"skip link: {link}")
                continue

            filename = os.path.basename(link)
            if ext in setting.module_ext:
                # PDF,zipはDLする。
                dst_dir = f'{pre}/{item["EDB-ID"]}'
                MyTool.shell_command(f"mkdir -p {dst_dir}")
                if MyHttp.download_file_to_dir(link, dst_dir):
                    msg_list.append(f"〇({filename})")
                else:
                    msg_list.append(f"〇(DL失敗: {filename})")

            else:
                logger.debug(f"skip filename: {filename}")
                # msg_list.append(f"不明({filename})")
        if msg_list:
            item["Exploit"] = "\n".join(msg_list)
        else:
            item["Exploit"] = "不明"

    else:
        logger.warning(f'path_ext: {item["Path"]}')
        item["Exploit"] = f"不明({path_ext})"


def main():
    pass


if __name__ == '__main__':
    main()
