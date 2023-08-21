import sys, re, lzma, base64, lzma, codecs, marshal, io, dis
def get_bytes(text):
    '''Get the bytes inside b'' '''
    return re.search(r"b'(.+)'", text).group(1)
def decompressing(payload):
    'Just removing the second layer xd'
    return lzma.decompress(codecs.escape_decode(get_bytes(payload.decode()))[0]).decode()
def start_deobf():
    'getting the compressed bytes and the payload'
    return disasm(decompressing(lzma.decompress(base64.b64decode(get_bytes(open(sys.argv[1],'r',encoding='utf-8').read())))))
def disasm(text):
    'Gettings the strings and deobfuscate the code'
    matches = re.findall(r'\b(_{4,9})\b="(.*?)"', text, re.DOTALL)
    variable_content = {name: content for name, content in matches}
    variable_list = []
    for name, content in variable_content.items():
        variable_list.append((name, content))
    disassembly_output = io.StringIO()
    original_stdout = sys.stdout
    try:
        sys.stdout = disassembly_output
        dis.dis(marshal.loads(base64.b64decode(codecs.decode(variable_list[0][1], 'rot13')+variable_list[2][1]+variable_list[3][1][::-1]+variable_list[1][1])))
    finally:
        sys.stdout = original_stdout
    disassembly_text = disassembly_output.getvalue()
    with open("disassembly_code.txt", "w") as f:
        f.write(disassembly_text)
        f.close()
    print('The asm code saved as: "disassembly_code.txt"')

if __name__ == '__main__':
    start_deobf()