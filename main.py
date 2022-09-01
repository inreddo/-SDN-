# coding: utf-8

import sys

from ryu.cmd import manager


def main():
    # 用要调试的脚本的完整路径取代就可以了
    sys.argv.append("/home/user/IPv4/traffic_manager.py")
    # sys.argv.append("--verbose")
    sys.argv.append("--observe-links")
    manager.main()

if __name__ == "__main__":
    main()
