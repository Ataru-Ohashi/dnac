# -*- coding: utf-8 -*-
"""
Driver class for "DNAC API"
"""
import base64
import json
import logging.config
import os
import sys
from time import sleep
import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import aide

__updated__ = "2021-08-24"

#------------------------------------------------------------------------------ AIDE python telemetry agent
try:
    aide.submit_statistics(
        pid=951228,  # This should be a valid PID
        tool_id="81262",
        metadata={
            "potential_savings": 3.0,  # Hours
            "report_savings": True,
        },
    )
except Exception:
    pass

#------------------------------------------------------------------------------ Variables


#------------------------------------------------------------------------------ Functions
#===============================================================================
# get_exec_dir
#===============================================================================
def get_exec_dir():
    """
    Pythonの実行ディレクトリパスを取得する。
    'python xxx.py' で実行したPythonファイルのパスが取得できる。

    Parameters
    ----------

    Returns
    -------
    _ : dict
        実行ディレクトリパス

    Raises
    ------
    """
    return os.path.dirname(__file__).replace("\\", "/")


#===============================================================================
# load_json_file
#===============================================================================
def load_json_file(file_path):
    """
    JSONファイルをロードする。
    ファイルが無い場合は空のdictを返却する。

    Parameters
    ----------
    file_path : str
        JSONファイルパス

    Returns
    -------
    _ : dict
        パラメータマップ

    Raises
    ------
    """
    if not os.path.isfile(file_path):
        logger = logging.getLogger(__name__)
        logger.warning(f"File not found: {file_path}")
        return {}

    with open(file_path, "r") as f:
        return json.load(f)


#===============================================================================
# base64_encode
#===============================================================================
def base64_encode(inputStr):
    """
    文字列をBase64でエンコードする。
    内部的には、一旦byte列に変換してエンコードしてからstrにデコードしている。

    Parameters
    ----------
    inputStr : str
        エンコード対象文字列

    Returns
    -------
    _ : str
        エンコード済み文字列

    Raises
    ------
    """
    return base64.b64encode(inputStr.encode()).decode()

#------------------------------------------------------------------------------ Classes


#===============================================================================
# CiscoAPIDriver
#===============================================================================
class CiscoAPIDriver:
    """
    各APIドライバーのスーパークラス
    """

    #===========================================================================
    # __init__
    #===========================================================================
    def __init__(self, verify=True, logger=None):
        self.verify = verify
        self.logger = logger or logging.getLogger(__name__)
        return

    #===========================================================================
    # _send_http_request
    #===========================================================================
    def _send_http_request(self, api, header=None, payload=None, return_all=False):
        """
        HTTPリクエストの送信と、HTTPレスポンスの受信を行う共通処理。
        リターンコードの確認まで行い、データの確認は呼び元で行う。

        Parameters
        ----------
        api : tuple
            使用するHTTPリクエストとリクエスト先URLのタプル

        header : dict, default None
            リクエストヘッダー

        payload : dict, default None
            リクエストに添付するクエリデータ
            GETならURLに接続し、POSTならBodyに組み込む

        return_all : bool, default False
            レスポンスデータ全体を返却する場合に True を設定
            デフォルトではディクショナリ形式に変換して返却する

        Returns
        -------
        ret : dict or Response or None
            レスポンスデータを全体または変換後の形式で返却
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        self.logger.debug("{} START".format(sys._getframe().f_code.co_name))
        ret = None
        try_limit = 3  # とりあえず3回試行できるようにしておく
        retry_interval = 5
        for _ in range(1, try_limit, 1):
            try:
                self.logger.debug("Request URL: [{}] {}".format(api[0], api[1]))

                # リクエスト送信
                if api[0] == "GET":
                    res = requests.get(api[1], headers=header, params=payload, verify=self.verify)
                elif api[0] == "POST":
                    res = requests.post(api[1], headers=header, data=json.dumps(payload), verify=self.verify)

                # リターンコードが 200 台でない場合に例外を送出
                res.raise_for_status()

                status_code = res.status_code
                self.logger.debug(f"Return Code: {status_code}")
                ret = res if return_all else res.json()
                break

            # 接続エラー系は再実行
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as e:
                self.logger.exception(f"HTTP connection error: {e}")
                sleep(retry_interval)

            # 上記以外の例外は異常終了
            except Exception as e:
                self.logger.exception(f"Unexpected error: {e}")
                if res is not None:
                    self.logger.error(f"Return data: {res.text}")
                break

        self.logger.debug("{} END".format(sys._getframe().f_code.co_name))
        return ret


#===============================================================================
# DNACDriver
#===============================================================================
class DNACDriver(CiscoAPIDriver):

    #===========================================================================
    # __init__
    #===========================================================================
    def __init__(self, verify=True, logger=None):
        super().__init__(verify=verify, logger=logger)
        config = load_json_file("%s/%s" % (get_exec_dir(), "config.json"))
        self.hostname = config["hostname"]
        self.username = config["username"]
        self.password = config["password"]
        self.zip_pass = config["zip_pass"]
        self.api_key = base64_encode(f"{self.username}:{self.password}")
        api = config["api"]["authenticationAPI"]
        self.authentication_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["getDeviceList"]
        self.get_device_list_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["exportDeviceConfigurations"]
        self.export_device_config_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["getTaskById"]
        self.get_task_by_id_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["downloadAFileByFileId"]
        self.download_a_file_by_file_id_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["getClientDetail"]
        self.get_client_detail_api = (api[0], self.__create_url(api[1]))
        api = config["api"]["getClientEnrichmentDetails"]
        self.get_client_enrichment_details_api = (api[0], self.__create_url(api[1]))

        self.token = None
        return

    #===========================================================================
    # __create_url
    #===========================================================================
    def __create_url(self, api_path):
        """
        パスにプロトコルとFQDNを接続し、HTTPリクエスト用URLを生成する。

        Parameters
        ----------
        api_path : str
            APIパス
            先頭はスラッシュ "/" であること

        Returns
        -------
        _ : str
            HTTPリクエストURL
            パスがNone（設定が無い）の場合はNoneを返却する

        Raises
        ------
        """
        if api_path is None: return None
        return f"https://{self.hostname}:443{api_path}"

    #===========================================================================
    # __create_header
    #===========================================================================
    def __create_header(self, append=None, token=None):
        """
        HTTPリクエストヘッダを生成する。
        共通で以下のヘッダ情報を設定する。
            - Content-Type
            - Accept
            - x-auth-token

        Parameters
        ----------
        append : dict, default None
            追加で設定するヘッダ情報のマップ

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        ret : dict
            HTTPリクエストヘッダ

        Raises
        ------
        """
        ret = {"Content-Type":"application/json",
               "Accept": "application/json",
               "x-auth-token": token or self.token}
        if append is not None: ret.update(append)
        return ret

    #===========================================================================
    # get_token
    #===========================================================================
    def get_token(self):
        """
        APIへのリクエスト時に必要なトークンを取得する。
        最初にこのメソッドを実行しないと、以降のリクエストに必要なトークンが得られない。
        トークンはインスタンス内部にも記録するため、インスタンスを保持する場合はトークンを指定する必要は無い。

        Parameters
        ----------

        Returns
        -------
        _ : str or None
            トークンを返却
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        header = self.__create_header(append={"Authorization": f"Basic {self.api_key}"})
        data = self._send_http_request(self.authentication_api, header=header)
        if data is None: return None

        self.token = data["Token"]
        return self.token

    #===========================================================================
    # get_devices
    #===========================================================================
    def get_devices(self, hostname=None, token=None):
        """
        指定したデバイスのリストを取得する。
        条件を指定しない場合、DNACに登録されている全てのデバイスを取得する。

        Parameters
        ----------
        hostname : str, default None
            デバイスのホスト名を指定する場合に設定
            ワイルドカード使用可

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : list or None
            デバイスのリストを返却
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        header = self.__create_header(token=token)
        payload = {}
        if hostname is not None:
            payload["hostname"] = hostname
        data = self._send_http_request(self.get_device_list_api,
                                       header=header,
                                       payload=payload if len(payload) else None)
        if data is None: return None

        return data["response"]

    #===========================================================================
    # kick_export_configs
    #===========================================================================
    def kick_export_configs(self, ids, token=None):
        """
        指定したデバイスのConfigを暗号化Zip形式でエクスポートする。
        Configはクリアテキスト形式で出力され、パスワード等の文字列はマスクされない。
        暗号化Zipのパスワードは「[ユーザ名]：[パスワード]」となる。
        ※ここではエクスポート処理をキックするだけで、ダウンロードはできない。

        Parameters
        ----------
        ids : list
            Config出力対象となるデバイスのIDリスト

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : list or None
            エクスポートプロセスのタスクIDを返却
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        header = self.__create_header(token=token)
        payload = {"deviceId": ids,
                   "password": self.zip_pass}
        data = self._send_http_request(self.export_device_config_api, header=header, payload=payload)
        if data is None: return None

        return data["response"]["taskId"]

    #===========================================================================
    # get_task_status
    #===========================================================================
    def get_task_status(self, task_id, token=None):
        """
        指定したタスクの状態を取得する。

        Parameters
        ----------
        task_id : str
            対象タスクのID

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : list or None
            レスポンスデータ
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        header = self.__create_header(token=token)
        api = (self.get_task_by_id_api[0],
               self.get_task_by_id_api[1].format(taskId=task_id))
        data = self._send_http_request(api, header=header)
        if data is None: return None

        return data["response"]

    #===========================================================================
    # download_file
    #===========================================================================
    def download_file(self, file_id=None, additional_status_url=None, token=None):
        """
        指定したファイルをダウンロードする。
        ファイルIDまたは追加URLのいずれかを指定すること。
        両方を指定した場合はファイルIDを優先する。
        両方を指定しない場合はFalseを返却する。

        Parameters
        ----------
        file_id : str, default None
            対象ファイルのID

        additional_status_url : str, default None
            ファイル生成タスクから入手したダウンロードURL

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : bool
            ダウンロードに成功した場合はTrue
            それ以外の場合はFalse

        Raises
        ------
        """
        header = self.__create_header(token=token)
        if file_id is not None:
            api = (self.download_a_file_by_file_id_api[0],
                   self.download_a_file_by_file_id_api[1].format(fileId=file_id))
        elif additional_status_url is not None:
            api = (self.download_a_file_by_file_id_api[0],
                   self.__create_url(additional_status_url))
        else:
            self.logger.warning("It is mandatory to set either 'file_id' or 'additional_status_url'")
            return False

        res = self._send_http_request(api, header=header, return_all=True)
        if res is None: return False

        # レスポンスヘッダからファイル名を取得
        content_disposition = res.headers["Content-Disposition"]
        filename_attribute = "filename="
        filename = content_disposition[content_disposition.find(filename_attribute) + len(filename_attribute):]
        filename = filename.replace("\"", "")

        # バイナリデータとしてファイル出力
        with open("%s/%s" % (get_exec_dir(), filename), "wb") as f:
            f.write(res.content)

        return True

    #===========================================================================
    # get_client
    #===========================================================================
    def get_client(self, mac, timestamp=None, token=None):
        """
        指定したクライアントの詳細情報を取得する。

        Parameters
        ----------
        mac : str
            対象クライアントのMACアドレス

        timestamp : int or None, default blank
            特定の時間の情報を取得したい場合に設定
            設定値はエポック時間（ミリ秒単位）
            設定しない場合は最新の情報を取得

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : dict or None
            レスポンスデータ
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        header = self.__create_header(token=token)
        payload = {"timestamp": "" if timestamp is None else str(timestamp),
                   "macAddress": mac}
        data = self._send_http_request(self.get_client_detail_api, header=header, payload=payload)
        if data is None: return None

        return data

    #===========================================================================
    # get_client_enrichment
    #===========================================================================
    def get_client_enrichment(self, entity_type, entity_value, issue_category=None, token=None):
        """
        指定したクライアントに発生している異常および改善策を取得する。

        Parameters
        ----------
        entity_type : str
            対象クライアントを特定するためのキー
            "network_user_id" または "mac_address"

        entity_value : str
            キーに対するパラメータ
            ユーザIDまたはMACアドレス

        issue_category : str, default None
            イベントのカテゴリを絞り込む場合に設定

        token : str, default None
            リクエストに必要なトークンを外部から指定する場合に設定
            設定しない場合、インスタンス内に保持しているトークンを使用する

        Returns
        -------
        _ : dict or None
            レスポンスデータ
            リクエストに失敗した場合はNone

        Raises
        ------
        """
        header = self.__create_header(append={"entity_type": entity_type,
                                              "entity_value": entity_value,
                                              "issueCategory": "" if issue_category is None else issue_category},
                                      token=token)
        data = self._send_http_request(self.get_client_enrichment_details_api, header=header)
        if data is None: return None

        # HTTPレスポンスは 200 でデータにエラーが入ってるパターンがある
        if "errorCode" in data:
            self.logger.error("Return error : [{}] {}".format(data["errorCode"], data["errorDescription"]))
            return None

        return data

    #===========================================================================
    # get_client_enrichment_by_mac
    #===========================================================================
    def get_client_enrichment_by_mac(self, mac, issue_category=None, token=None):
        """
        get_client_enrichment() のラッパー関数。
        """
        return self.get_client_enrichment("mac_address", mac, issue_category, token)

    #===========================================================================
    # get_client_enrichment_by_uid
    #===========================================================================
    def get_client_enrichment_by_uid(self, uid, issue_category=None, token=None):
        """
        get_client_enrichment() のラッパー関数。
        """
        return self.get_client_enrichment("network_user_id", uid, issue_category, token)


#------------------------------------------------------------------------------ Main
if __name__ == "__main__":

    # 引数チェック
    argv = sys.argv
    argc = len(argv)
    if argc != 2:
        print("Usage:")
        print("    python %s <operation-type>" % argv[0])
        print("Operation-Type:")
        print("    --get-device-config : Get configuration for all devices that DNAC has")
        quit(255)

    # ロガーの初期化
    logging.config.fileConfig("%s/%s" % (get_exec_dir(), "log.conf"))
    logger = logging.getLogger(__name__)

    logger.info("PROCESS START")

    # TODO: DNACが自己証明書を使ってるとSSL証明書の検証でエラーが発生するので検証をOFFする
    # TODO: 検証をOFFすると InsecureRequestWarning が出るので、それも無視する
    urllib3.disable_warnings(InsecureRequestWarning)
    driver = DNACDriver(verify=False)

    if argv[1] == "--get-device-config":
        logger.info("Get token")
        token = driver.get_token()
        if token is None:
            logger.error("Can not get token")
            quit(255)
        logger.debug(f"Get token : {token}")

        logger.info("Get device list")
        devices = driver.get_devices()
        if devices is None:
            logger.error("Can not get device list")
            quit(255)

        # デバイスIDリストを作成
        device_ids = []
        device_table = "{0:32} {1:15} {2:12} {3:18} {4:12} {5:16} {6:40}"
        logger.debug(device_table.format("Hostname",
                                         "Mgmt IP",
                                         "Serial",
                                         "Platform",
                                         "SW Version",
                                         "Role",
                                         "ID"))
        for dev in devices:
            logger.debug(device_table.format(str(dev["hostname"]),
                                             str(dev["managementIpAddress"]),
                                             str(dev["serialNumber"]),
                                             str(dev["platformId"]),
                                             str(dev["softwareVersion"]),
                                             str(dev["role"]),
                                             str(dev["id"])))
            # 以下のデバイスはConfig収集対象から外す
            # * WLCにJoinしたAP
            # * 3rd Party製デバイス
            if (dev["associatedWlcIp"] == "" and dev["deviceSupportLevel"] == "Supported"):
                device_ids.append(dev["id"])

        if len(device_ids) == 0:
            logger.info("There are no devices exporting config")
            quit(0)

        # Config Exportプロセスをキック
        logger.info("Start config export process")
        task_id = driver.kick_export_configs(device_ids)
        if task_id is None:
            logger.error("Can not start config export process")
            quit(255)

        # プロセス終了まで待機
        while True:
            sleep(3)
            data = driver.get_task_status(task_id)
            if data is None:
                logger.error("Can not get process status")
                quit(255)
            elif data["isError"]:
                logger.error(data["progress"])
                quit(255)

            logger.info(data["progress"])
            dl_url = data.get("additionalStatusURL")
            if dl_url is not None:
                break

        driver.download_file(additional_status_url=dl_url)

    else:
        logger.warning("Unknown operation type")

    logger.info("PROCESS END")
    quit(0)
