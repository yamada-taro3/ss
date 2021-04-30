# coding=utf-8

import os.path
import urllib.error
import urllib.request
import urllib.parse
import logging

logger = logging.getLogger(__name__)


def get_request3(base_url, path="", header={"Accept-Language": "ja_JP", }, charset="utf-8"):
    """
        汎用のGetRequest発行関数
    """
#    logger.debug('DEBUGレベルのメッセージです')
#    logger.info('INFOレベルのメッセージです')
#    logger.warning('WARNINGレベルのメッセージです')
#    logger.error('ERRORレベルのメッセージです')
#    logger.critical('CRITICALレベルのメッセージです')
    body = ""
    if base_url:
        req = urllib.request.Request(base_url, headers=header)
        try:
            with urllib.request.urlopen(req) as res:
                body = res.read().decode(charset)
#            print(body)
        except urllib.error.HTTPError as e:
            if e.code >= 400:
                print(e.reason)
            else:
                raise e
    else:
        logger.error(f"""入力値エラー
  base_url={base_url}
  path    ={path}
  header  ={header}""")

    return body


def download_file(url, dst_path):
    result = False
    try:
        with urllib.request.urlopen(url) as web_file:
            data = web_file.read()
            with open(dst_path, mode='wb') as local_file:
                local_file.write(data)
                result = True
    except urllib.error.URLError as e:
        logger.warning(f"urllib.error.URLError e: {e} {url}")
    # except urllib.error.HTTPError as e:
    #     logger.warning(f"urllib.error.HTTPError e: {e}")
    # except urllib.error.ContentTooShortError as e:
    #     logger.warning(f"urllib.error.ContentTooShortError e: {e}")
    finally:
        return result


def download_file_to_dir(url, dst_dir):
    return download_file(url, os.path.join(dst_dir, os.path.basename(url)))
