from mitmproxy import http, ctx, command
from mitmproxy.addonmanager import Loader
import re
import sys


class AdvancedLogger:
    def __init__(self):
        self.request_count = 0
        self.filter_pattern = None

        # 设置系统标准输出编码为UTF-8
        sys.stdout.reconfigure(encoding='utf-8')

    def load(self, loader: Loader):
        """Addon加载时调用"""
        ctx.log.info("AdvancedLogger loaded. Use 'advancedlogger.set_filter' to set filter pattern.")

    @command.command("advancedlogger.set_filter")
    def set_filter(self, pattern: str) -> str:
        """设置流量过滤正则表达式"""
        try:
            re.compile(pattern)
            self.filter_pattern = pattern
            ctx.log.alert(f"✅ Filter set: {pattern}")
            return f"Filter updated to: {pattern}"
        except re.error as e:
            return f"❌ Invalid regex: {e}"

    def request(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1
        ctx.log.info(f"🔍 Checking request #{self.request_count}: {flow.request.url}")

        # 始终记录完整日志
        self._save_complete_log(flow, is_request=True)

        # 仅当匹配时才记录到过滤日志
        if self.filter_pattern and re.search(self.filter_pattern, flow.request.url):
            ctx.log.alert(f"🎯 MATCHED request #{self.request_count}")
            self._save_filtered_log(flow, is_request=True)

    def response(self, flow: http.HTTPFlow) -> None:
        # 始终记录完整日志
        self._save_complete_log(flow, is_request=False)

        # 仅当匹配时才记录到过滤日志
        if self.filter_pattern and re.search(self.filter_pattern, flow.request.url):
            self._save_filtered_log(flow, is_request=False)

    def _log_request(self, flow):
        ctx.log.info(f"\n=== Request #{self.request_count} ===")
        ctx.log.info(f"From: {flow.client_conn.address[0]}")
        ctx.log.info(f"To: {flow.server_conn.address[0] if flow.server_conn else 'Unknown'}")
        ctx.log.info(f"URL: {flow.request.pretty_url}")

    def _log_response(self, flow):
        ctx.log.info(f"=== Response for Request #{self.request_count} ===")
        ctx.log.info(f"Status: {flow.response.status_code}")

    def _save_complete_log(self, flow, is_request: bool):
        """始终记录所有流量到完整日志"""
        with open("traffic_log.txt", "a", encoding='utf-8') as f:
            self._write_flow_to_file(f, flow, is_request)

    def _save_filtered_log(self, flow, is_request: bool):
        """仅记录匹配流量到过滤日志"""
        with open("filtered_traffic.txt", "a", encoding='utf-8') as f:
            self._write_flow_to_file(f, flow, is_request)

    def _write_flow_to_file(self, file_obj, flow, is_request: bool):
        """通用写入方法"""
        try:
            if is_request:
                file_obj.write(f"\n=== Request #{self.request_count} ===\n")
                file_obj.write(f"{flow.request.method} {flow.request.url}\n")
                file_obj.write("Headers:\n")
                for k, v in flow.request.headers.items():
                    file_obj.write(f"{k}: {v}\n")
                if flow.request.content:
                    file_obj.write("\nBody:\n")
                    file_obj.write(flow.request.content.decode('utf-8', errors='replace'))
            else:
                file_obj.write(f"\n=== Response ===\n")
                file_obj.write(f"Status: {flow.response.status_code}\n")
                file_obj.write("Headers:\n")
                for k, v in flow.response.headers.items():
                    file_obj.write(f"{k}: {v}\n")
                if flow.response.content:
                    file_obj.write("\nBody:\n")
                    file_obj.write(flow.response.content.decode('utf-8', errors='replace'))
        except UnicodeEncodeError:
            # 处理编码错误
            ctx.log.warn("Unicode encode error occurred when writing to file")


addons = [
    AdvancedLogger()
]