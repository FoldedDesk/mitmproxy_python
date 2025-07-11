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

        if not self.filter_pattern or re.search(self.filter_pattern, flow.request.url):
            ctx.log.alert(f"🎯 MATCHED request #{self.request_count}")
            self._log_request(flow)
            self._save_to_file(flow, is_request=True)

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.filter_pattern or re.search(self.filter_pattern, flow.request.url):
            self._log_response(flow)
            self._save_to_file(flow, is_request=False)

    def _log_request(self, flow):
        ctx.log.info(f"\n=== Request #{self.request_count} ===")
        ctx.log.info(f"From: {flow.client_conn.address[0]}")
        ctx.log.info(f"To: {flow.server_conn.address[0] if flow.server_conn else 'Unknown'}")
        ctx.log.info(f"URL: {flow.request.pretty_url}")

    def _log_response(self, flow):
        ctx.log.info(f"=== Response for Request #{self.request_count} ===")
        ctx.log.info(f"Status: {flow.response.status_code}")

    def _save_to_file(self, flow, is_request: bool):
        """安全写入文件，处理编码问题"""

        def safe_write(file, text):
            try:
                file.write(text)
            except UnicodeEncodeError:
                # 替换非法字符
                file.write(text.encode('utf-8', errors='replace').decode('utf-8'))

        # 1. 始终记录到traffic_log.txt
        with open("traffic_log.txt", "a", encoding='utf-8') as f:
            self._write_flow_to_file(f, flow, is_request, safe_write)

        # 2. 匹配的流量额外记录到filtered_traffic.txt
        if not self.filter_pattern or re.search(self.filter_pattern, flow.request.url):
            with open("filtered_traffic.txt", "a", encoding='utf-8') as f:
                self._write_flow_to_file(f, flow, is_request, safe_write)

    def _write_flow_to_file(self, file_obj, flow, is_request: bool, write_func):
        """通用写入方法"""
        if is_request:
            write_func(file_obj, f"\n=== Request #{self.request_count} ===\n")
            write_func(file_obj, f"{flow.request.method} {flow.request.url}\n")
            write_func(file_obj, "Headers:\n")
            for k, v in flow.request.headers.items():
                write_func(file_obj, f"{k}: {v}\n")
            if flow.request.content:
                write_func(file_obj, "\nBody:\n")
                write_func(file_obj, flow.request.content.decode('utf-8', errors='replace'))
        else:
            write_func(file_obj, f"\n=== Response ===\n")
            write_func(file_obj, f"Status: {flow.response.status_code}\n")
            write_func(file_obj, "Headers:\n")
            for k, v in flow.response.headers.items():
                write_func(file_obj, f"{k}: {v}\n")
            if flow.response.content:
                write_func(file_obj, "\nBody:\n")
                write_func(file_obj, flow.response.content.decode('utf-8', errors='replace'))


addons = [
    AdvancedLogger()
]