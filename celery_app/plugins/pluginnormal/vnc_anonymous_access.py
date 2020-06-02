import logging
from Crypto.Cipher import DES
import socket
from time import sleep

from celery_app.utils.utils import insert_vuln_db


#VNC 允许匿名访问
plugin_id=59
default_port_list=[80,5900,5901,5902,5903,5904,5905,5906,5907]

key_codes = {
    "XK_space": 0x0020,  # U+0020 SPACE
    "XK_exclam": 0x0021,  # U+0021 EXCLAMATION MARK
    "XK_quotedbl": 0x0022,  # U+0022 QUOTATION MARK
    "XK_numbersign": 0x0023,  # U+0023 NUMBER SIGN
    "XK_dollar": 0x0024,  # U+0024 DOLLAR SIGN
    "XK_percent": 0x0025,  # U+0025 PERCENT SIGN
    "XK_ampersand": 0x0026,  # U+0026 AMPERSAND
    "XK_apostrophe": 0x0027,  # U+0027 APOSTROPHE
    "XK_quoteright": 0x0027,  # deprecated
    "XK_parenleft": 0x0028,  # U+0028 LEFT PARENTHESIS
    "XK_parenright": 0x0029,  # U+0029 RIGHT PARENTHESIS
    "XK_asterisk": 0x002a,  # U+002A ASTERISK
    "XK_plus": 0x002b,  # U+002B PLUS SIGN
    "XK_comma": 0x002c,  # U+002C COMMA
    "XK_minus": 0x002d,  # U+002D HYPHEN-MINUS
    "XK_period": 0x002e,  # U+002E FULL STOP
    "XK_slash": 0x002f,  # U+002F SOLIDUS
    "XK_0": 0x0030,  # U+0030 DIGIT ZERO
    "XK_1": 0x0031,  # U+0031 DIGIT ONE
    "XK_2": 0x0032,  # U+0032 DIGIT TWO
    "XK_3": 0x0033,  # U+0033 DIGIT THREE
    "XK_4": 0x0034,  # U+0034 DIGIT FOUR
    "XK_5": 0x0035,  # U+0035 DIGIT FIVE
    "XK_6": 0x0036,  # U+0036 DIGIT SIX
    "XK_7": 0x0037,  # U+0037 DIGIT SEVEN
    "XK_8": 0x0038,  # U+0038 DIGIT EIGHT
    "XK_9": 0x0039,  # U+0039 DIGIT NINE
    "XK_colon": 0x003a,  # U+003A COLON
    "XK_semicolon": 0x003b,  # U+003B SEMICOLON
    "XK_less": 0x003c,  # U+003C LESS-THAN SIGN
    "XK_equal": 0x003d,  # U+003D EQUALS SIGN
    "XK_greater": 0x003e,  # U+003E GREATER-THAN SIGN
    "XK_question": 0x003f,  # U+003F QUESTION MARK
    "XK_at": 0x0040,  # U+0040 COMMERCIAL AT
    "XK_A": 0x0041,  # U+0041 LATIN CAPITAL LETTER A
    "XK_B": 0x0042,  # U+0042 LATIN CAPITAL LETTER B
    "XK_C": 0x0043,  # U+0043 LATIN CAPITAL LETTER C
    "XK_D": 0x0044,  # U+0044 LATIN CAPITAL LETTER D
    "XK_E": 0x0045,  # U+0045 LATIN CAPITAL LETTER E
    "XK_F": 0x0046,  # U+0046 LATIN CAPITAL LETTER F
    "XK_G": 0x0047,  # U+0047 LATIN CAPITAL LETTER G
    "XK_H": 0x0048,  # U+0048 LATIN CAPITAL LETTER H
    "XK_I": 0x0049,  # U+0049 LATIN CAPITAL LETTER I
    "XK_J": 0x004a,  # U+004A LATIN CAPITAL LETTER J
    "XK_K": 0x004b,  # U+004B LATIN CAPITAL LETTER K
    "XK_L": 0x004c,  # U+004C LATIN CAPITAL LETTER L
    "XK_M": 0x004d,  # U+004D LATIN CAPITAL LETTER M
    "XK_N": 0x004e,  # U+004E LATIN CAPITAL LETTER N
    "XK_O": 0x004f,  # U+004F LATIN CAPITAL LETTER O
    "XK_P": 0x0050,  # U+0050 LATIN CAPITAL LETTER P
    "XK_Q": 0x0051,  # U+0051 LATIN CAPITAL LETTER Q
    "XK_R": 0x0052,  # U+0052 LATIN CAPITAL LETTER R
    "XK_S": 0x0053,  # U+0053 LATIN CAPITAL LETTER S
    "XK_T": 0x0054,  # U+0054 LATIN CAPITAL LETTER T
    "XK_U": 0x0055,  # U+0055 LATIN CAPITAL LETTER U
    "XK_V": 0x0056,  # U+0056 LATIN CAPITAL LETTER V
    "XK_W": 0x0057,  # U+0057 LATIN CAPITAL LETTER W
    "XK_X": 0x0058,  # U+0058 LATIN CAPITAL LETTER X
    "XK_Y": 0x0059,  # U+0059 LATIN CAPITAL LETTER Y
    "XK_Z": 0x005a,  # U+005A LATIN CAPITAL LETTER Z
    "XK_bracketleft": 0x005b,  # U+005B LEFT SQUARE BRACKET
    "XK_backslash": 0x005c,  # U+005C REVERSE SOLIDUS
    "XK_bracketright": 0x005d,  # U+005D RIGHT SQUARE BRACKET
    "XK_asciicircum": 0x005e,  # U+005E CIRCUMFLEX ACCENT
    "XK_underscore": 0x005f,  # U+005F LOW LINE
    "XK_grave": 0x0060,  # U+0060 GRAVE ACCENT
    "XK_quoteleft": 0x0060,  # deprecated
    "XK_a": 0x0061,  # U+0061 LATIN SMALL LETTER A
    "XK_b": 0x0062,  # U+0062 LATIN SMALL LETTER B
    "XK_c": 0x0063,  # U+0063 LATIN SMALL LETTER C
    "XK_d": 0x0064,  # U+0064 LATIN SMALL LETTER D
    "XK_e": 0x0065,  # U+0065 LATIN SMALL LETTER E
    "XK_f": 0x0066,  # U+0066 LATIN SMALL LETTER F
    "XK_g": 0x0067,  # U+0067 LATIN SMALL LETTER G
    "XK_h": 0x0068,  # U+0068 LATIN SMALL LETTER H
    "XK_i": 0x0069,  # U+0069 LATIN SMALL LETTER I
    "XK_j": 0x006a,  # U+006A LATIN SMALL LETTER J
    "XK_k": 0x006b,  # U+006B LATIN SMALL LETTER K
    "XK_l": 0x006c,  # U+006C LATIN SMALL LETTER L
    "XK_m": 0x006d,  # U+006D LATIN SMALL LETTER M
    "XK_n": 0x006e,  # U+006E LATIN SMALL LETTER N
    "XK_o": 0x006f,  # U+006F LATIN SMALL LETTER O
    "XK_p": 0x0070,  # U+0070 LATIN SMALL LETTER P
    "XK_q": 0x0071,  # U+0071 LATIN SMALL LETTER Q
    "XK_r": 0x0072,  # U+0072 LATIN SMALL LETTER R
    "XK_s": 0x0073,  # U+0073 LATIN SMALL LETTER S
    "XK_t": 0x0074,  # U+0074 LATIN SMALL LETTER T
    "XK_u": 0x0075,  # U+0075 LATIN SMALL LETTER U
    "XK_v": 0x0076,  # U+0076 LATIN SMALL LETTER V
    "XK_w": 0x0077,  # U+0077 LATIN SMALL LETTER W
    "XK_x": 0x0078,  # U+0078 LATIN SMALL LETTER X
    "XK_y": 0x0079,  # U+0079 LATIN SMALL LETTER Y
    "XK_z": 0x007a,  # U+007A LATIN SMALL LETTER Z
    "XK_braceleft": 0x007b,  # U+007B LEFT CURLY BRACKET
    "XK_bar": 0x007c,  # U+007C VERTICAL LINE
    "XK_braceright": 0x007d,  # U+007D RIGHT CURLY BRACKET
    "XK_asciitilde": 0x007e,  # U+007E TILDE

    "XK_BackSpace": 0xff08,  # Back space, back char
    "XK_Tab": 0xff09,
    "XK_Linefeed": 0xff0a,  # Linefeed, LF
    "XK_Clear": 0xff0b,
    "XK_Return": 0xff0d,  # Return, enter
    "XK_Pause": 0xff13,  # Pause, hold
    "XK_Scroll_Lock": 0xff14,
    "XK_Sys_Req": 0xff15,
    "XK_Escape": 0xff1b,
    "XK_Delete": 0xffff,  # Delete, rubout

    "XK_Home": 0xff50,
    "XK_Left": 0xff51,  # Move left, left arrow
    "XK_Up": 0xff52,  # Move up, up arrow
    "XK_Right": 0xff53,  # Move right, right arrow
    "XK_Down": 0xff54,  # Move down, down arrow
    "XK_Prior": 0xff55,  # Prior, previous
    "XK_Page_Up": 0xff55,
    "XK_Next": 0xff56,  # Next
    "XK_Page_Down": 0xff56,
    "XK_End": 0xff57,  # EOL
    "XK_Begin": 0xff58,  # BOL

    "XK_Shift_L": 0xffe1,  # Left shift
    "XK_Shift_R": 0xffe2,  # Right shift
    "XK_Control_L": 0xffe3,  # Left control
    "XK_Control_R": 0xffe4,  # Right control
    "XK_Caps_Lock": 0xffe5,  # Caps lock
    "XK_Shift_Lock": 0xffe6,  # Shift lock

    "XK_Meta_L": 0xffe7,  # Left meta
    "XK_Meta_R": 0xffe8,  # Right meta
    "XK_Alt_L": 0xffe9,  # Left alt
    "XK_Alt_R": 0xffea,  # Right alt
    "XK_Super_L": 0xffeb,  # Left super
    "XK_Super_R": 0xffec,  # Right super
    "XK_Hyper_L": 0xffed,  # Left hyper
    "XK_Hyper_R": 0xffee,  # Right hyper
}


def socket_receive(sock, size):
    res = b""
    while len(res) < size:
        res += sock.recv(size - len(res))

    return res


class VNCException(Exception):
    pass


class VNC(object):

    def __init__(self, ip, port, timeout):

        self.ip = ip
        self.port = port
        self.timeout = timeout

    def connect(self):
        self.sock = socket.create_connection((self.ip, self.port), timeout=self.timeout)

        # == Banner ==

        resp = socket_receive(self.sock, 12)

        if resp[:3] != b"RFB":
            raise Exception("Wrong protocol")

        self.version = resp[:11].decode('ascii')

        logging.info("Server version : %s" % self.version)

        major, minor = int(self.version[6]), int(self.version[10])

        if (major, minor) in [(3, 8), (4, 1)]:
            proto = b'RFB 003.008\n'
        elif (major, minor) == (3, 7):
            proto = b'RFB 003.007\n'
        else:
            proto = b'RFB 003.003\n'

        self.sock.sendall(proto)

        sleep(0.5)

        # == Security types ==

        self.supported_security_types = []

        if major == 4 or (major, minor) in [(3, 7), (3, 8)]:
            resp = socket_receive(self.sock, 1)

            if len(resp) == 0:
                raise VNCException("Protocol error")

            nb_security_types = ord(resp)

            if nb_security_types == 0:
                resp = socket_receive(self.sock, 4)

                msg_len = int.from_bytes(resp, byteorder="big")
                resp = socket_receive(self.sock, msg_len)

                msg = resp.decode("utf-8")
                raise VNCException(msg)

            logging.info("%s Security types" % nb_security_types)

            resp = socket_receive(self.sock, nb_security_types)

            for index in range(0, nb_security_types):
                sec_type_id = int(resp[index])
                self.supported_security_types.append(security_type_from_id(sec_type_id))
                logging.info("> %s" % security_type_from_id(sec_type_id))
        else:
            resp = socket_receive(self.sock, 4)

            if len(resp) == 0:
                raise VNCException("Protocol error")

            sec_type_id = ord(resp[3:4])

            if sec_type_id == 0:
                resp = socket_receive(self.sock, 4)

                msg_len = int.from_bytes(resp, byteorder="big")
                resp = socket_receive(self.sock, msg_len)

                msg = resp.decode("utf-8")
                raise VNCException(msg)

            self.supported_security_types.append(security_type_from_id(sec_type_id))
            logging.info("> %s" % security_type_from_id(sec_type_id))

    def auth(self, auth_type, password=None):

        major, minor = int(self.version[6]), int(self.version[10])

        if auth_type == "None":
            if major == 4 or (major == 3 and minor >= 8):
                self.sock.sendall(b"\x01")
                self.authenticated = True
            elif major == 3 and minor == 7:
                self.sock.sendall(b"\x01")
                self.authenticated = True
                return 0, 'OK'
            else:
                self.authenticated = True
                return 0, 'OK'
        elif auth_type == "VNC Authentication":
            if major == 4 or (major == 3 and minor >= 7):
                self.sock.sendall(b"\x02")

            challenge = socket_receive(self.sock, 16)

            if len(challenge) != 16:
                raise VNCException("Wrong challenge length")

            logging.debug('challenge: %s' % challenge)
            password = password.ljust(8, '\x00')[:8]  # make sure it is 8 chars long, zero padded

            key = self.gen_key(password)
            logging.debug('key: %s' % key)

            des = DES.new(key, DES.MODE_ECB)
            enc = des.encrypt(challenge)

            logging.debug('enc: %s' % enc)
            self.sock.sendall(enc)

        resp = socket_receive(self.sock, 4)
        logging.debug('resp: %s' % repr(resp))

        response_code = ord(resp[3:4])
        mesg = resp[8:].decode('ascii', 'ignore')

        if response_code == 0:
            self.authenticated = True
            return response_code, 'OK'
        else:
            if major == 4 or (major == 3 and minor >= 8):
                resp = socket_receive(self.sock, 4)

                msg_len = int.from_bytes(resp, byteorder="big")
                resp = socket_receive(self.sock, msg_len)

                msg = resp.decode("utf-8")
                return response_code, msg

            else:
                if response_code == 1:
                    return response_code, "failed"
                elif response_code == 2:
                    return response_code, "failed, too many attempts"
                else:
                    raise VNCException('Unknown response: %d' % (response_code))

    def gen_key(self, key):
        newkey = []
        for ki in range(len(key)):
            bsrc = ord(key[ki])
            btgt = 0
            for i in range(8):
                if bsrc & (1 << i):
                    btgt = btgt | (1 << 7 - i)
            newkey.append(btgt)
        return bytes(newkey)

    def init(self):

        self.sock.sendall(b'\x01')

        resp = socket_receive(self.sock, 20)

        self.frame_width = int.from_bytes(resp[:2], "big")
        self.frame_height = int.from_bytes(resp[2:4], "big")

        resp = socket_receive(self.sock, 4)
        name_len = int.from_bytes(resp, "big")
        resp = socket_receive(self.sock, name_len)
        self.name = resp.decode()

        logging.info("Server name: %s" % self.name)

        # set pixel mode

        payload = b"\x00"
        payload += b"\x00\x00\x00"  # Padding
        payload += (32).to_bytes(1, byteorder="big")  # Pixel size
        payload += (24).to_bytes(1, byteorder="big")  # Depth
        payload += (0).to_bytes(1, byteorder="big")  # Big endian flag
        payload += (1).to_bytes(1, byteorder="big")  # True color flag
        payload += (255).to_bytes(2, byteorder="big")  # Red maximum
        payload += (255).to_bytes(2, byteorder="big")  # Green maximum
        payload += (255).to_bytes(2, byteorder="big")  # Blue maximum
        payload += (0).to_bytes(1, byteorder="big")  # Red shift
        payload += (8).to_bytes(1, byteorder="big")  # Green shift
        payload += (16).to_bytes(1, byteorder="big")  # Blue shift
        payload += b"\x00\x00\x00"  # Padding
        self.sock.sendall(payload)

        # set encoding

        payload = b"\x02"
        payload += b"\x00"  # Padding
        payload += (1).to_bytes(2, byteorder="big")  # Number encoding
        payload += (0).to_bytes(4, byteorder="big")  # - Raw
        self.sock.sendall(payload)

    def disconnect(self):
        self.sock.close()


def security_type_from_id(sec_type_id):
    if sec_type_id == 0:
        return "Invalid"
    elif sec_type_id == 1:
        return "None"
    elif sec_type_id == 2:
        return "VNC Authentication"
    elif sec_type_id >= 3 and sec_type_id <= 15:
        return "RealVNC"
    elif sec_type_id == 16:
        return "Tight"
    elif sec_type_id == 17:
        return "Ultra"
    elif sec_type_id == 18:
        return "TLS"
    elif sec_type_id == 19:
        return "VeNCrypt"
    elif sec_type_id == 20:
        return "GTK-VNC SASL"
    elif sec_type_id == 21:
        return "MD5 hash authentication"
    elif sec_type_id == 22:
        return "Colin Dean xvp"
    elif sec_type_id == 23:
        return "Secure Tunnel"
    elif sec_type_id == 24:
        return "Integrated SSH"
    elif sec_type_id >= 25 and sec_type_id <= 29:
        return "Unassigned"
    elif sec_type_id >= 30 and sec_type_id <= 35:
        return "Apple Inc."
    elif sec_type_id >= 36 and sec_type_id <= 127:
        return "Unassigned"
    elif sec_type_id >= 128 and sec_type_id <= 255:
        return "RealVNC"


def getSpecialKeyCode(key):
    key_lower = key.lower()

    if key_lower in ["gui", "super", "windows"]:
        return key_codes["XK_Super_L"]
    if key_lower in ["alt"]:
        return key_codes["XK_Alt_L"]
    if key_lower in ["shift"]:
        return key_codes["XK_Shift_L"]
    if key_lower in ["control", "ctrl"]:
        return key_codes["XK_Control_L"]
    if key_lower in ["enter"]:
        return key_codes["XK_Return"]
    if key_lower in ["tab"]:
        return key_codes["XK_Tab"]
    if key_lower in ["backspace"]:
        return key_codes["XK_BackSpace"]
    if key_lower in ["clear"]:
        return key_codes["XK_Clear"]
    if key_lower in ["delete", "del"]:
        return key_codes["XK_Delete"]
    if key_lower in ["escape"]:
        return key_codes["XK_Escape"]
    if key_lower in ["space"]:
        return key_codes["XK_space"]
    if key_lower in ["downarrow", "down"]:
        return key_codes["XK_Down"]
    if key_lower in ["uparrow", "up"]:
        return key_codes["XK_Up"]
    elif len(key) == 1:
        return ord(key)
    else:
        return key_codes["XK_%s" % key]


def check_anonymous(host, port=5901):
    vnc = VNC(host, port, timeout=10)
    try:
        vnc.connect()
    except VNCException as e:
        return False

    if "None" in vnc.supported_security_types:
        return True, vnc
    elif "VNC Authentication" in vnc.supported_security_types:
        return False, vnc
    else:
        return False, None


def check(host, port=5901):
    target = '{}:{}'.format(host, port)
    try:
        result, vnc = check_anonymous(host, port)

        if result:
            code, msg = vnc.auth("None")
            vnc.disconnect()
            if code == 0:
                output = '开启匿名访问'
                insert_vuln_db(host, target, output, plugin_id)
                return True, host, target, output
    except:
        return False
    return False

