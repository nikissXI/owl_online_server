from asyncio import (
    create_subprocess_exec,
    gather,
    subprocess,
    sleep,
    run,
)
from asyncio.exceptions import IncompleteReadError, TimeoutError
from ujson import loads
from traceback import format_exc
from struct import pack, unpack
from socket import AF_PACKET, SOCK_RAW, socket
from re import sub


class GV(object):
    # need to modify
    intface = "interface_name"   # your vpn interface name
    tshark_path = "/usr/bin/tshark"   # your tshark path
    # a.b.c.d, here use 10.5.0.0/16
    ipv4_a = 10
    ipv4_b = 5

    get_wgnum_count = 100
    rooms = {}
    forward_once = {}
    send_socket = socket(AF_PACKET, SOCK_RAW)
    _instance = None

    def __new__(cls, *args, **kw):
        if cls._instance is None:
            cls._instance = object.__new__(cls, *args, **kw)
        return cls._instance

    def __init__(self):
        pass


gv = GV()
gv.send_socket.bind((gv.intface, 0))

# 校验和计算
def get_checksum(data: bytes) -> int:
    sum = 0
    data = unpack(f"!{int(len(data)/4)}I", data)
    for i in data:
        sum = sum + i
        sum = (sum >> 16) + (sum & 0xFFFF)
    sum = (sum >> 16) + (sum & 0xFFFF)
    return ~sum & 0xFFFF


# 发送房间列表
async def send_room_list(fangzhu_ip_list, finder_ip, dst_port):
    # 目标地址
    dst_addr = [gv.ipv4_a, gv.ipv4_b, int(finder_ip[5:6]), int(finder_ip[7:])]
    # 源地址
    src_addr = [gv.ipv4_a, gv.ipv4_b, 255, 1]

    notice_room = b'\xc4 \xb7\xe6|=%+\x17\x00tcp4://localhost:6797/\xb5\xf1\xf5\x05\x04\xff\xd8\xa9?\x00{"snn":"connection succeeded","mcc":1,"ccc":1,"hsb":true,"v":"1.99.6"}'
    # 重新计算房间json字符串长度
    notice_room = sub(
        b'.{2}{"s',
        pack("!B", len(notice_room) - notice_room.find(b'\x00{"s', 30)) + b'\x00{"s',
        notice_room,
        count=1,
        flags=0,
    )
    # 发送数据包
    udp_len = 8 + len(notice_room)
    gv.send_socket.send(
        # 由于大部分数据都可以固定的，所以直接用数字
        pack(
            "!BBHHHBBH4B4B",
            69,  # 头部长度和版本
            0,  # 服务
            20 + udp_len,  # 数据包总长度
            8888,  # 标识
            16384,  # flags和offset
            64,  # ttl
            17,  # 协议
            get_checksum(
                pack(
                    "!BBHHHBBH4B4B",
                    69,  # 头部长度和版本
                    0,  # 服务
                    20 + udp_len,  # 数据包总长度
                    8888,  # 标识
                    16384,  # flags和offset
                    64,  # ttl
                    17,  # 协议
                    0,  # 校验和
                    *src_addr,  # 源IP
                    *dst_addr,  # 目的IP
                )
            ),
            *src_addr,  # 源IP
            *dst_addr,  # 目的IP
        )
        + pack("!HHHH", 46797, dst_port, udp_len, 0)  # 源端口  # 目的端口  # UDP长度  # 校验和
        + notice_room  # 数据
    )

    # 遍历房间列表
    for i in fangzhu_ip_list:
        # 如果搜自己房间跳过
        if i == finder_ip or gv.rooms[i][1] == 0:
            continue

        room_tmp = bytes.fromhex(gv.rooms[i][1])
        udp_len = 8 + len(room_tmp)
        src_addr = [gv.ipv4_a, gv.ipv4_b, int(i[5:6]), int(i[7:])]
        gv.send_socket.send(
            # 由于大部分数据都可以固定的，所以直接用数字
            pack(
                "!BBHHHBBH4B4B",
                69,  # 头部长度和版本
                0,  # 服务
                20 + udp_len,  # 数据包总长度
                8888,  # 标识
                16384,  # flags和offset
                64,  # ttl
                17,  # 协议
                get_checksum(
                    pack(
                        "!BBHHHBBH4B4B",
                        69,  # 头部长度和版本
                        0,  # 服务
                        20 + udp_len,  # 数据包总长度
                        8888,  # 标识
                        16384,  # flags和offset
                        64,  # ttl
                        17,  # 协议
                        0,  # 校验和
                        *src_addr,  # 源IP
                        *dst_addr,  # 目的IP
                    )
                ),
                *src_addr,  # 源IP
                *dst_addr,  # 目的IP
            )
            + pack("!HHHH", 46797, dst_port, udp_len, 0)  # 源端口  # 目的端口  # UDP长度  # 校验和
            + room_tmp  # 数据
        )


# 数据包回调函数
async def packet_called(p):
    try:
        # 接收房间信息
        if p["ip_dst"][0] == f"{gv.ipv4_a}.{gv.ipv4_b}.255.1":
            gv.rooms[p["ip_src"][0]] = [3, p["data"][0]]
            print("get a new room")

        # 返回房间列表信息给搜房者
        else:
            finder_ip = p["ip_src"][0]
            src_port = p["udp_srcport"][0]
            # 判断是否发送过房间列表
            if finder_ip in gv.forward_once.keys():
                # 如果端口号一样代表发送过，就不处理
                if gv.forward_once[finder_ip] == src_port:
                    return
            # 没发送过就记录本次来源的IP和端口号
            else:
                gv.forward_once[finder_ip] = src_port
            # 返回房间列表
            await send_room_list(list(gv.rooms), finder_ip, int(src_port))
    except Exception:
        error_msg = format_exc()
        print(f"数据包回调函数出错!\n错误追踪:\n{error_msg}\n数据包:{p}")


async def read_stdout(proc: subprocess.Process):
    try:
        p_count = 0
        # 抓够100W次就结束子进程，释放内存
        while p_count < 1000000:
            p_count += 1
            buf = await proc.stdout.readuntil(separator=b"\n")
            # 跳过分隔符
            if buf[:3] == b'{"i':
                continue
            else:
                # 解析json格式数据包
                p = loads(buf.decode())
                # 执行数据包回调
                await packet_called(p["layers"])

        # 重置次数，结束子进程
        proc.terminate()
    except IncompleteReadError:
        pass


async def sniff():
    while True:
        proc = await create_subprocess_exec(
            *[
                gv.tshark_path,
                "-i",
                gv.intface,
                "-l",
                "-n",
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "udp.srcport",
                "-e",
                "data",
                "-T",
                "ek",
                "-f",
                f"\
                (ip dst {gv.ipv4_a}.{gv.ipv4_b}.255.1 and udp dst port 12345 and udp src port 46797) or \
                (ip dst {gv.ipv4_a}.{gv.ipv4_b}.255.255 and udp dst port 46797)",
                # 1、捕获返回给服务器的房间信息数据包
                # 2、捕获玩家搜房的广播包
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # 从管道读取内容
        await read_stdout(proc)
        # 等一秒，防止关机时又跑一遍
        await sleep(1)


async def check_room():
    while True:
        # 轮询房间信息
        def _get_room_info(i, j):
            # 发送数据包
            src_addr = [gv.ipv4_a, gv.ipv4_b, 255, 1]
            dst_addr = [gv.ipv4_a, gv.ipv4_b, i, j]
            gv.send_socket.send(
                # 由于大部分数据都可以固定的，所以直接用数字
                pack(
                    "!BBHHHBBH4B4B",
                    69,  # 头部长度和版本
                    0,  # 服务
                    36,  # 数据包总长度
                    8888,  # 标识
                    16384,  # flags和offset
                    64,  # ttl
                    17,  # 协议
                    get_checksum(
                        pack(
                            "!BBHHHBBH4B4B",
                            69,  # 头部长度和版本
                            0,  # 服务
                            36,  # 数据包总长度
                            8888,  # 标识
                            16384,  # flags和offset
                            64,  # ttl
                            17,  # 协议
                            0,  # 校验和
                            *src_addr,  # 源IP
                            *dst_addr,  # 目的IP
                        )
                    ),
                    *src_addr,  # 源IP
                    *dst_addr,  # 目的IP
                )
                + pack("!HHHH", 12345, 46797, 16, 0)  # 源端口 目的端口 UDP长度 校验和
                + b"\xc4\x20\xb7\xe6\x7c\x3d\x25\x2b"  # 数据
            )

        # 轮询房间信息
        send_cir = gv.get_wgnum_count // 255
        res_count = gv.get_wgnum_count % 255
        for i in range(0, send_cir + 1):
            if i != send_cir:
                for j in range(1, 256):
                    _get_room_info(i, j)
            else:
                for j in range(1, res_count + 1):
                    _get_room_info(i, j)

        await sleep(1)

        # 判断房间状态
        for fangzhu in list(gv.rooms):
            # 每轮减一次房间ttl
            if gv.rooms[fangzhu][0] > 0:
                gv.rooms[fangzhu][0] -= 1
            else:
                gv.rooms.pop(fangzhu)

        await sleep(5)


async def main():
    await gather(sniff(), check_room())


try:
    print("start")
    run(main())
except KeyboardInterrupt:
    print("stop")
