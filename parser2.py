import hashlib

class Decoder:
    def __init__(self, data):
        self.data = data
        self.index = 0

    def decode(self):
        # Nothing else to decode.
        if self.index >= len(self.data):
            return None

        # Get the current index character
        char = self.data[self.index:self.index + 1]

        if char == b'd':
            return self.decode_dict()
        elif char == b'l':
            return self.decode_list()
        elif char == b'i':
            return self.decode_int()
        elif b'0' <= char <= b'9':
            return self.decode_string()
        else:
            raise ValueError(f"Invalid bencode character at index {self.index}")

    def decode_dict(self):
        # d <key-value pairs> e
        dictionary = {}
        self.index += 1  

        while self.data[self.index:self.index + 1] != b'e':
            key = self.decode()
            value = self.decode()
            dictionary[key] = value

        self.index += 1  
        return dictionary

    def decode_list(self):
        lst = []
        self.index += 1  

        while self.data[self.index:self.index + 1] != b'e':
            lst.append(self.decode())

        self.index += 1  
        return lst

    def decode_int(self):
        # i<number>e
        self.index += 1  
        start = self.index

        while self.data[self.index:self.index + 1] != b'e':
            self.index += 1

        num = int(self.data[start:self.index])
        self.index += 1  
        return num

    def decode_string(self):
        start = self.index

        while self.data[self.index:self.index + 1] != b':':
            self.index += 1

        length = int(self.data[start:self.index])

        self.index += 1  

        s = self.data[self.index:self.index + length]
        self.index += length

        return s


class Parser:
    def __init__(self, torrent_file):
        self.torrent_file = torrent_file
        self.raw_data = None
        self.data = None
        self.info_start = None
        self.info_end = None
        self.info_hash = None

    def parse(self):
        with open(self.torrent_file, "rb") as f:
            self.raw_data = f.read()

        decoder = Decoder(self.raw_data)
        self.data = decoder.decode()

        self.find_info_region()
        self.info_hash = self.compute_info_hash()

        return self.data

    def find_info_region(self):
        data = self.raw_data
        index = 0

        while index < len(data):
            
            if data[index:index + 1].isdigit():
                colon = data.find(b':', index)
                if colon == -1:
                    break

                try:
                    strlen = int(data[index:colon])
                except ValueError:
                    index += 1
                    continue

                key_start = colon + 1
                key_end = key_start + strlen

                
                if data[key_start:key_end] == b"info":
                    self.info_start = key_end

                    d = Decoder(data)
                    d.index = self.info_start
                    d.decode()  

                    self.info_end = d.index
                    return

                index = key_end
                continue

            index += 1

        raise ValueError("Could not locate 'info' dictionary")

    def compute_info_hash(self):
        if self.info_start is None or self.info_end is None:
            raise ValueError("Info region not set")

        info_bytes = self.raw_data[self.info_start:self.info_end]
        return hashlib.sha1(info_bytes).digest()

    def get_info_hash(self):
        """
        Extract info_hash from parsed torrent data.
        """
        return self.info_hash
